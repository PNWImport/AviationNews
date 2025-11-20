"""
Contact Extraction Module for Aviation Intelligence Hub
Extracts names, titles, companies, and contact info from news articles
Integrates with Aviation.Contact for monetization
"""
import re
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any

log = logging.getLogger("aih")

# Job title patterns (aviation industry focused)
TITLE_PATTERNS = [
    # C-Suite
    r'\b(CEO|Chief Executive Officer)\b',
    r'\b(CFO|Chief Financial Officer)\b',
    r'\b(COO|Chief Operating Officer)\b',
    r'\b(CTO|Chief Technology Officer)\b',
    r'\b(CMO|Chief Marketing Officer)\b',
    r'\b(CHRO|Chief Human Resources Officer)\b',
    r'\b(Chief .+? Officer)\b',

    # Executive titles
    r'\b(President(?:\s+and\s+CEO)?)\b',
    r'\b(Vice President|VP)(?:\s+of\s+.+?)?\b',
    r'\b(Executive Vice President|EVP)\b',
    r'\b(Senior Vice President|SVP)\b',

    # Directors and Managers
    r'\b(Director(?:\s+of\s+.+?)?)\b',
    r'\b(Managing Director)\b',
    r'\b(General Manager|GM)\b',
    r'\b(Regional Manager)\b',

    # Aviation-specific
    r'\b(Captain|First Officer|Pilot)\b',
    r'\b(Flight Attendant|Cabin Crew)\b',
    r'\b(Air Traffic Controller)\b',
    r'\b(Aircraft Engineer|Maintenance Chief)\b',
    r'\b(Safety Officer|Safety Manager)\b',
    r'\b(Fleet Manager)\b',

    # Board and governance
    r'\b(Chairman|Chairwoman|Chair)\b',
    r'\b(Board Member|Board Director)\b',
    r'\b(Founder|Co-Founder)\b',
    r'\b(Partner|Managing Partner)\b',
]

# Compile title patterns
COMPILED_TITLES = [re.compile(pattern, re.IGNORECASE) for pattern in TITLE_PATTERNS]

# Name patterns (2-4 capitalized words, excluding common words)
NAME_PATTERN = re.compile(
    r'\b([A-Z][a-z]+(?:\s+(?:van|de|von|der|la|le|da|di|del))?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?(?:\s+[A-Z][a-z]+)?)\b'
)

# Email pattern
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Common words to exclude from names
EXCLUDE_WORDS = {
    'Airlines', 'Airport', 'Aviation', 'Boeing', 'Airbus', 'Federal', 'National',
    'Administration', 'Association', 'Corporation', 'Company', 'Limited',
    'International', 'American', 'United', 'Delta', 'Southwest', 'Spirit',
    'JetBlue', 'Frontier', 'Alaska', 'Hawaiian', 'Allegiant'
}


def extract_names_from_text(text: str) -> List[str]:
    """Extract potential person names from text"""
    if not text:
        return []

    matches = NAME_PATTERN.findall(text)

    # Filter out excluded words
    filtered = []
    for name in matches:
        # Skip if any word in the name is in exclude list
        words = name.split()
        if not any(word in EXCLUDE_WORDS for word in words):
            # Skip single-word names
            if len(words) >= 2:
                filtered.append(name)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for name in filtered:
        if name.lower() not in seen:
            seen.add(name.lower())
            unique.append(name)

    return unique


def extract_title_from_text(text: str, near_name: str = None) -> Optional[str]:
    """
    Extract job title from text
    If near_name is provided, look for title near that name
    """
    if not text:
        return None

    # If we have a name, search in a window around it
    search_text = text
    if near_name:
        # Find the name in text
        name_pos = text.lower().find(near_name.lower())
        if name_pos != -1:
            # Look 100 chars before and after the name
            start = max(0, name_pos - 100)
            end = min(len(text), name_pos + len(near_name) + 100)
            search_text = text[start:end]

    # Try each title pattern
    for pattern in COMPILED_TITLES:
        match = pattern.search(search_text)
        if match:
            return match.group(0).strip()

    return None


def extract_email_from_text(text: str) -> Optional[str]:
    """Extract email address from text"""
    if not text:
        return None

    match = EMAIL_PATTERN.search(text)
    if match:
        return match.group(0)

    return None


def extract_company_from_context(text: str, article_title: str = None) -> Optional[str]:
    """
    Extract company name from article context
    Looks for airline/manufacturer names
    """
    if not text:
        return None

    # Common aviation companies (prioritized list)
    companies = [
        'Boeing', 'Airbus', 'Lockheed Martin', 'Northrop Grumman', 'Raytheon',
        'General Electric', 'GE Aviation', 'Rolls-Royce', 'Pratt & Whitney',
        'American Airlines', 'Delta Air Lines', 'United Airlines', 'Southwest Airlines',
        'JetBlue Airways', 'Alaska Airlines', 'Spirit Airlines', 'Frontier Airlines',
        'Lufthansa', 'Air France', 'KLM', 'British Airways', 'Emirates', 'Qatar Airways',
        'Singapore Airlines', 'Cathay Pacific', 'JAL', 'ANA',
        'FAA', 'NTSB', 'EASA', 'ICAO', 'IATA'
    ]

    # Check title first (most likely to contain company)
    combined_text = f"{article_title or ''} {text}"

    for company in companies:
        if re.search(r'\b' + re.escape(company) + r'\b', combined_text, re.IGNORECASE):
            return company

    return None


def parse_name(full_name: str) -> Tuple[str, str]:
    """
    Parse full name into first and last name
    Returns: (first_name, last_name)
    """
    parts = full_name.strip().split()

    if len(parts) == 0:
        return "", ""
    elif len(parts) == 1:
        return parts[0], ""
    elif len(parts) == 2:
        return parts[0], parts[1]
    elif len(parts) == 3:
        # Middle name handling: "John Michael Smith" -> "John", "Smith"
        return parts[0], parts[-1]
    else:
        # Multiple parts: take first and last
        return parts[0], parts[-1]


def calculate_confidence_score(name: str, title: str, company: str, email: str, context: str) -> float:
    """
    Calculate confidence score for extracted contact
    Score from 0.0 to 1.0
    """
    score = 0.3  # Base score

    # Name quality (20%)
    if name and len(name.split()) >= 2:
        score += 0.2

    # Title presence (25%)
    if title:
        score += 0.25
        # Bonus for C-suite
        if any(x in title.upper() for x in ['CEO', 'CFO', 'COO', 'CTO', 'PRESIDENT', 'CHIEF']):
            score += 0.05

    # Company presence (20%)
    if company:
        score += 0.20

    # Email presence (rare but valuable) (20%)
    if email:
        score += 0.20

    # Context quality (15%)
    if context and len(context) > 50:
        score += 0.10

    return min(1.0, score)


def extract_contacts_from_article(
    article_id: int,
    article_title: str,
    article_content: str,
    ai_summary: str
) -> List[Dict[str, Any]]:
    """
    Extract all contacts mentioned in an article
    Returns list of contact dictionaries
    """
    contacts = []

    # Combine text sources (prioritize AI summary)
    full_text = f"{ai_summary or ''}\n\n{article_title or ''}\n\n{article_content or ''}"

    # Extract all potential names
    names = extract_names_from_text(full_text)

    if not names:
        return contacts

    log.info(f"Found {len(names)} potential contacts in article {article_id}: {names}")

    # For each name, extract associated information
    for name in names:
        # Extract title near this name
        title = extract_title_from_text(full_text, name)

        # Extract company
        company = extract_company_from_context(full_text, article_title)

        # Extract email (rare)
        email = extract_email_from_text(full_text)

        # Get context snippet (150 chars around the name)
        name_pos = full_text.lower().find(name.lower())
        if name_pos != -1:
            start = max(0, name_pos - 75)
            end = min(len(full_text), name_pos + len(name) + 75)
            context = full_text[start:end].strip()
        else:
            context = ai_summary[:150] if ai_summary else article_title[:150]

        # Parse name into components
        first_name, last_name = parse_name(name)

        # Calculate confidence
        confidence = calculate_confidence_score(name, title, company, email, context)

        # Skip low-confidence extractions
        if confidence < 0.4:
            log.debug(f"Skipping low-confidence contact: {name} (score: {confidence:.2f})")
            continue

        contact = {
            'name': name,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'company': company,
            'title': title,
            'confidence_score': confidence,
            'context': context,
            'source_article_id': article_id
        }

        contacts.append(contact)

    return contacts


def save_or_update_contact(db, contact_data: Dict[str, Any]) -> int:
    """
    Save contact to database or update if exists
    Returns contact ID
    """
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()

    name = contact_data['name']
    company = contact_data.get('company')

    # Check if contact exists (same name + company)
    cursor.execute("""
        SELECT id, mention_count, first_mentioned_date
        FROM contacts
        WHERE name = ? AND (company = ? OR (company IS NULL AND ? IS NULL))
    """, (name, company, company))

    existing = cursor.fetchone()

    if existing:
        # Update existing contact
        contact_id = existing['id']
        new_mention_count = existing['mention_count'] + 1

        # Keep first_mentioned_date, update last_mentioned_date
        cursor.execute("""
            UPDATE contacts
            SET title = COALESCE(?, title),
                email = COALESCE(?, email),
                linkedin_url = COALESCE(?, linkedin_url),
                last_mentioned_date = ?,
                mention_count = ?,
                updated_at = ?,
                confidence_score = MAX(confidence_score, ?)
            WHERE id = ?
        """, (
            contact_data.get('title'),
            contact_data.get('email'),
            contact_data.get('linkedin_url'),
            now,
            new_mention_count,
            now,
            contact_data['confidence_score'],
            contact_id
        ))

        log.info(f"Updated existing contact: {name} (ID: {contact_id}, mentions: {new_mention_count})")
    else:
        # Create new contact
        cursor.execute("""
            INSERT INTO contacts (
                name, first_name, last_name, email, company, title,
                linkedin_url, confidence_score,
                first_mentioned_date, last_mentioned_date, mention_count,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            contact_data.get('first_name'),
            contact_data.get('last_name'),
            contact_data.get('email'),
            company,
            contact_data.get('title'),
            contact_data.get('linkedin_url'),
            contact_data['confidence_score'],
            now,
            now,
            1,
            now,
            now
        ))

        contact_id = cursor.lastrowid
        log.info(f"Created new contact: {name} (ID: {contact_id})")

    db.commit()
    return contact_id


def save_contact_mention(db, contact_id: int, contact_data: Dict[str, Any]) -> bool:
    """
    Save mention of contact in article
    Returns True if created, False if already exists
    """
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()

    article_id = contact_data['source_article_id']

    # Check if mention already exists
    cursor.execute("""
        SELECT id FROM contact_mentions
        WHERE contact_id = ? AND news_item_id = ?
    """, (contact_id, article_id))

    if cursor.fetchone():
        return False  # Already exists

    # Create mention
    cursor.execute("""
        INSERT INTO contact_mentions (
            contact_id, news_item_id, context,
            title_at_time, company_at_time, confidence_score,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        contact_id,
        article_id,
        contact_data.get('context'),
        contact_data.get('title'),
        contact_data.get('company'),
        contact_data['confidence_score'],
        now
    ))

    db.commit()
    return True


def process_article_for_contacts(
    db,
    article_id: int,
    article_title: str,
    article_content: str,
    ai_summary: str
) -> int:
    """
    Extract and save all contacts from an article
    Returns number of contacts extracted
    """
    # Extract contacts from article
    contacts = extract_contacts_from_article(
        article_id, article_title, article_content, ai_summary
    )

    if not contacts:
        return 0

    # Save each contact
    for contact_data in contacts:
        try:
            contact_id = save_or_update_contact(db, contact_data)
            save_contact_mention(db, contact_id, contact_data)
        except Exception as e:
            log.error(f"Error saving contact {contact_data['name']}: {e}")

    log.info(f"Processed article {article_id}: extracted {len(contacts)} contacts")
    return len(contacts)
