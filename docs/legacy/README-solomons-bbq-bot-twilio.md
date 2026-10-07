# Solomon's Famous BBQ - Phone Bot (Matlacha)

A Twilio-powered AI phone bot for Solomon's Famous BBQ in Matlacha, Florida.

## Business Info (Updated from website)
- **Name**: Solomon's Famous BBQ
- **Address**: 4590 Pine Island Rd, Matlacha, FL 33993
- **Phone**: (706) 371-8211
- **Hours**: Saturdays 12:00 PM – 7:00 PM (or until sold out). Catering available daily.
- **Highlights**: Fall-off-the-bone brisket, Rockin' Rib Dinner, pulled pork by the pound
- **Special**: FREE drink with any brisket or rib purchase
- **Signature**: "Oink Oink" the smoker + 42 years of experience by owner Solomon

## Features
- Answers calls 24/7
- Provides hours, menu, directions
- Takes takeout orders (simulated)
- Answers FAQs
- Transfers to human if needed

## Quick Start

1. Install dependencies:
```bash
npm install
```

2. Set environment variables (create `.env`):
```
TWILIO_ACCOUNT_SID=your_sid
TWILIO_AUTH_TOKEN=your_token
TWILIO_PHONE_NUMBER=your_twilio_number
OPENAI_API_KEY=your_openai_key   # optional for smarter responses
```

3. Run the server:
```bash
npm start
```

4. Configure your Twilio number's Voice webhook to:
`https://your-ngrok-url.ngrok.io/voice`

## Files
- `server.js` - Main Twilio webhook + AI handler
- `bot-logic.js` - Conversation logic and responses
- `menu.json` - Restaurant menu

The bot is ready to deploy!