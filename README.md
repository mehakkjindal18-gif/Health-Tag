# HealthTag prototype

A working demo of the three-tier emergency access flow from the PPT.

| Who scans the QR | What they see |
|---|---|
| Anyone (no sign-in) | "Call 108" and the emergency contact's number. No medical data, no name. |
| Verified doctor or paramedic | The emergency card: blood group, allergies, conditions, medications. Logged against their ID. |
| Same responder, after the emergency contact approves | Full history and hospital notes, for 30 minutes. |

Every access goes into an activity log, and the owner gets a notification each time.

## Run it (2 minutes)

```
pip install -r requirements.txt
python app.py
```

The terminal prints two addresses:
- `http://localhost:5000` for the laptop
- `http://192.168.x.x:5000` for phones on the **same Wi-Fi**. The QR codes point at this address.

If `cryptography` won't install, the app still works. It just stores data as plain text and says so in the page footer.

## Demo script (about 3 minutes)

1. Open the home page. Scan the QR on it with a phone: you see only "Call 108" and the contact number.
2. Tap "Verify and open the medical card". Sign in as **H-1001 / 1234** (Dr. Anita Verma, Apollo Hospital) or **A-2002 / 1234** (paramedic). The emergency card opens.
3. Tap **Request full history**. Open **Demo inbox** on the laptop: Neha (the contact) has been sent a code and an approval link.
4. Open the approval link (pretend it's on Neha's phone) and tap **Approve access**. The responder's screen unlocks by itself. You can also type the 6-digit code from the inbox instead.
5. Add a treatment note on the responder screen.
6. Open the owner dashboard (home page > Owner dashboard). It lists every scan, request, approval and note.
7. To show onboarding: **Create a HealthTag**, fill the form, and show the printable card.

## If the venue Wi-Fi blocks phone-to-laptop traffic

- Turn on a **mobile hotspot** on one phone, and connect the laptop and the second phone to it. Restart `python app.py` so it picks up the new address.
- Or use a tunnel and tell the app its public address:
  `HEALTHTAG_BASE_URL=https://your-tunnel-url python app.py` (on Windows: `set HEALTHTAG_BASE_URL=...` first).
- On Windows, allow Python through the firewall the first time it asks.
- Fallback with no phone at all: open the links on the laptop. Everything works in one browser, using a private window for the "contact".

## What is real and what is simulated

Real: the three access tiers, credential check with hashed PINs, one-time code with 3 attempts, approval by link, request expiry (15 min), access expiry (30 min), audit log, owner notifications, hospital notes, QR generation, encryption of medical fields in the database file.

Simulated for the demo: SMS and app notifications (they appear in the Demo inbox), and hospital/ambulance verification (three seeded accounts). In the full system these use an SMS gateway and a registry check at onboarding.

Not built yet (say these as next steps): offline cache on the phone, ABHA integration, HTTPS, CSRF protection, rate limiting.

## Files

- `app.py`: the whole backend (routes, access rules, database)
- `templates/`, `static/style.css`: the screens
- `healthtag.db`, `.healthtag.key`, `.secret_key`: created on first run. **Delete all three to reset the demo.**
