"""
Contact Management Module for Aviation Intelligence Hub
CRUD operations, saved contacts, export functionality
"""
import csv
import io
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple

log = logging.getLogger("aih")


def get_all_contacts(db, limit: int = 100, offset: int = 0, search: str = None,
                     company_filter: str = None, min_confidence: float = 0.0) -> List[Dict[str, Any]]:
    """
    Get all contacts with optional filtering
    """
    cursor = db.cursor()

    query = """
        SELECT id, name, first_name, last_name, email, company, title,
               confidence_score, mention_count, first_mentioned_date, last_mentioned_date
        FROM contacts
        WHERE 1=1
    """
    params = []

    if search:
        query += " AND (name LIKE ? OR company LIKE ? OR title LIKE ?)"
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])

    if company_filter:
        query += " AND company = ?"
        params.append(company_filter)

    if min_confidence > 0:
        query += " AND confidence_score >= ?"
        params.append(min_confidence)

    query += " ORDER BY mention_count DESC, confidence_score DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    return [dict(row) for row in cursor.fetchall()]


def get_contact_by_id(db, contact_id: int) -> Optional[Dict[str, Any]]:
    """Get single contact by ID with full details"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT id, name, first_name, last_name, email, company, title,
               linkedin_url, confidence_score, mention_count,
               first_mentioned_date, last_mentioned_date,
               aviation_contact_id, synced_to_aviation_contact,
               created_at, updated_at
        FROM contacts
        WHERE id = ?
    """, (contact_id,))

    row = cursor.fetchone()
    return dict(row) if row else None


def get_contact_mentions(db, contact_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """Get all article mentions for a contact"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            cm.id, cm.context, cm.title_at_time, cm.company_at_time,
            cm.confidence_score, cm.created_at,
            n.id as article_id, n.airline as article_title,
            n.source, n.date as article_date, n.sentiment, n.sentiment_label
        FROM contact_mentions cm
        JOIN news_items n ON cm.news_item_id = n.id
        WHERE cm.contact_id = ?
        ORDER BY n.date DESC
        LIMIT ?
    """, (contact_id, limit))

    return [dict(row) for row in cursor.fetchall()]


def get_contact_stats(db) -> Dict[str, Any]:
    """Get overall contact statistics"""
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM contacts")
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as total FROM contacts WHERE email IS NOT NULL")
    with_email = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as total FROM contacts WHERE title IS NOT NULL")
    with_title = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(DISTINCT company) as total FROM contacts WHERE company IS NOT NULL")
    unique_companies = cursor.fetchone()['total']

    cursor.execute("SELECT AVG(confidence_score) as avg FROM contacts")
    avg_confidence = cursor.fetchone()['avg'] or 0

    cursor.execute("SELECT COUNT(*) as total FROM contact_mentions")
    total_mentions = cursor.fetchone()['total']

    return {
        'total_contacts': total,
        'with_email': with_email,
        'with_title': with_title,
        'unique_companies': unique_companies,
        'avg_confidence': round(avg_confidence, 2),
        'total_mentions': total_mentions
    }


def get_top_companies(db, limit: int = 20) -> List[Dict[str, Any]]:
    """Get companies with most contacts"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT company, COUNT(*) as contact_count
        FROM contacts
        WHERE company IS NOT NULL
        GROUP BY company
        ORDER BY contact_count DESC
        LIMIT ?
    """, (limit,))

    return [dict(row) for row in cursor.fetchall()]


# ============================================================================
# SAVED CONTACTS
# ============================================================================

def check_saved_contacts_limit(db, user_id: int) -> Tuple[bool, int, int]:
    """
    Check if user has reached saved contacts limit
    Returns: (can_save, current_count, limit)
    Free: 10, Pro: unlimited
    """
    from gamification import is_pro_user

    # Pro users have unlimited
    if is_pro_user(db, user_id):
        return True, 0, -1  # -1 indicates unlimited

    # Free users: 10 saved contacts
    cursor = db.cursor()
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM saved_contacts
        WHERE user_id = ? AND is_deleted = 0
    """, (user_id,))

    result = cursor.fetchone()
    current_count = result['count'] if result else 0
    limit = 10

    can_save = current_count < limit
    return can_save, current_count, limit


def save_contact(db, user_id: int, contact_id: int, notes: str = None) -> Tuple[bool, str]:
    """
    Save a contact for a user
    Returns: (success, message)
    """
    # Check if already saved
    cursor = db.cursor()
    cursor.execute("""
        SELECT id, is_deleted FROM saved_contacts
        WHERE user_id = ? AND contact_id = ?
    """, (user_id, contact_id))

    existing = cursor.fetchone()
    if existing and not existing['is_deleted']:
        return False, "Contact already saved"

    # Check limit
    can_save, current_count, limit = check_saved_contacts_limit(db, user_id)
    if not can_save:
        return False, f"Free users can save up to {limit} contacts. Upgrade to Pro for unlimited!"

    now = datetime.utcnow().isoformat()

    if existing:
        # Undelete existing save
        cursor.execute("""
            UPDATE saved_contacts
            SET is_deleted = 0, saved_at = ?, notes = ?
            WHERE id = ?
        """, (now, notes, existing['id']))
    else:
        # Create new save
        cursor.execute("""
            INSERT INTO saved_contacts (user_id, contact_id, saved_at, notes, is_deleted)
            VALUES (?, ?, ?, ?, 0)
        """, (user_id, contact_id, now, notes))

    db.commit()
    return True, "Contact saved successfully"


def unsave_contact(db, user_id: int, contact_id: int) -> Tuple[bool, str]:
    """
    Unsave a contact (soft delete)
    Returns: (success, message)
    """
    cursor = db.cursor()
    cursor.execute("""
        UPDATE saved_contacts
        SET is_deleted = 1
        WHERE user_id = ? AND contact_id = ?
    """, (user_id, contact_id))

    if cursor.rowcount > 0:
        db.commit()
        return True, "Contact removed from saved"

    return False, "Contact was not saved"


def get_saved_contacts(db, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """Get user's saved contacts"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            c.id, c.name, c.first_name, c.last_name, c.email, c.company, c.title,
            c.confidence_score, c.mention_count,
            sc.saved_at, sc.notes
        FROM saved_contacts sc
        JOIN contacts c ON sc.contact_id = c.id
        WHERE sc.user_id = ? AND sc.is_deleted = 0
        ORDER BY sc.saved_at DESC
        LIMIT ?
    """, (user_id, limit))

    return [dict(row) for row in cursor.fetchall()]


def is_contact_saved(db, user_id: int, contact_id: int) -> bool:
    """Check if contact is saved by user"""
    cursor = db.cursor()
    cursor.execute("""
        SELECT id FROM saved_contacts
        WHERE user_id = ? AND contact_id = ? AND is_deleted = 0
    """, (user_id, contact_id))

    return cursor.fetchone() is not None


def update_saved_contact_notes(db, user_id: int, contact_id: int, notes: str) -> Tuple[bool, str]:
    """Update notes for a saved contact"""
    cursor = db.cursor()
    cursor.execute("""
        UPDATE saved_contacts
        SET notes = ?
        WHERE user_id = ? AND contact_id = ? AND is_deleted = 0
    """, (notes, user_id, contact_id))

    if cursor.rowcount > 0:
        db.commit()
        return True, "Notes updated"

    return False, "Contact not found in saved list"


# ============================================================================
# EXPORT FUNCTIONALITY (Pro Feature)
# ============================================================================

def export_contacts_to_csv(db, user_id: int, contact_ids: List[int] = None) -> str:
    """
    Export contacts to CSV format
    Returns CSV string
    """
    cursor = db.cursor()

    if contact_ids:
        # Export specific contacts
        placeholders = ','.join(['?' for _ in contact_ids])
        cursor.execute(f"""
            SELECT name, first_name, last_name, email, company, title,
                   linkedin_url, mention_count, confidence_score
            FROM contacts
            WHERE id IN ({placeholders})
            ORDER BY name
        """, contact_ids)
    else:
        # Export all saved contacts for user
        cursor.execute("""
            SELECT c.name, c.first_name, c.last_name, c.email, c.company, c.title,
                   c.linkedin_url, c.mention_count, c.confidence_score, sc.notes
            FROM saved_contacts sc
            JOIN contacts c ON sc.contact_id = c.id
            WHERE sc.user_id = ? AND sc.is_deleted = 0
            ORDER BY c.name
        """, (user_id,))

    contacts = cursor.fetchall()

    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'Name', 'First Name', 'Last Name', 'Email', 'Company', 'Title',
        'LinkedIn URL', 'Mentions', 'Confidence Score', 'Notes'
    ])

    # Data
    for contact in contacts:
        row = [
            contact['name'] or '',
            contact['first_name'] or '',
            contact['last_name'] or '',
            contact['email'] or '',
            contact['company'] or '',
            contact['title'] or '',
            contact.get('linkedin_url') or '',
            contact['mention_count'] or 0,
            f"{contact['confidence_score']:.2f}" if contact['confidence_score'] else '',
            contact.get('notes') or ''
        ]
        writer.writerow(row)

    # Log export
    cursor.execute("""
        INSERT INTO contact_exports (user_id, export_type, contact_count, created_at)
        VALUES (?, 'csv', ?, ?)
    """, (user_id, len(contacts), datetime.utcnow().isoformat()))
    db.commit()

    return output.getvalue()


def export_contacts_to_vcard(db, user_id: int, contact_ids: List[int] = None) -> str:
    """
    Export contacts to vCard format
    Returns vCard string
    """
    cursor = db.cursor()

    if contact_ids:
        placeholders = ','.join(['?' for _ in contact_ids])
        cursor.execute(f"""
            SELECT name, first_name, last_name, email, company, title
            FROM contacts
            WHERE id IN ({placeholders})
        """, contact_ids)
    else:
        cursor.execute("""
            SELECT c.name, c.first_name, c.last_name, c.email, c.company, c.title
            FROM saved_contacts sc
            JOIN contacts c ON sc.contact_id = c.id
            WHERE sc.user_id = ? AND sc.is_deleted = 0
        """, (user_id,))

    contacts = cursor.fetchall()

    vcards = []
    for contact in contacts:
        vcard = "BEGIN:VCARD\n"
        vcard += "VERSION:3.0\n"
        vcard += f"FN:{contact['name']}\n"

        if contact['first_name'] or contact['last_name']:
            vcard += f"N:{contact['last_name'] or ''};{contact['first_name'] or ''};;;\n"

        if contact['email']:
            vcard += f"EMAIL;TYPE=WORK:{contact['email']}\n"

        if contact['company']:
            vcard += f"ORG:{contact['company']}\n"

        if contact['title']:
            vcard += f"TITLE:{contact['title']}\n"

        vcard += "END:VCARD\n"
        vcards.append(vcard)

    # Log export
    cursor.execute("""
        INSERT INTO contact_exports (user_id, export_type, contact_count, created_at)
        VALUES (?, 'vcard', ?, ?)
    """, (user_id, len(contacts), datetime.utcnow().isoformat()))
    db.commit()

    return '\n'.join(vcards)


def get_user_export_history(db, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
    """Get user's contact export history"""
    cursor = db.cursor()

    cursor.execute("""
        SELECT id, export_type, contact_count, created_at
        FROM contact_exports
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (user_id, limit))

    return [dict(row) for row in cursor.fetchall()]
