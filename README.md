# Sentinel SOC 🛡️

Sentinel SOC is an intelligent, real-time Security Operations Center (SOC) system and dashboard. It continuously monitors system logs, performs rapid rule-based pre-filtering, and leverages AI (OpenAI) to classify and automatically respond to potential security threats.

## 🚀 Features
- **Real-Time Log Ingestion**: Streams and processes logs continuously in the background.
- **Rule-Based Triage (Gatekeeper)**: Fast, efficient rule-based triage to detect common attack patterns, such as:
  - Brute force login attempts
  - SQL injection patterns
  - Port scanning and probing
- **AI Threat Analysis (AI Analyst)**: Uses OpenAI to classify flagged logs with deep context, assigning severity levels (`low`, `medium`, `high`), determining the attack type, and providing detailed reasoning.
- **Automated Response (Decision Maker)**: Automatically takes action based on the AI's determined severity:
  - `High`: Blocks the offending IP address and alerts immediately.
  - `Medium`: Alerts administrators of highly suspicious activity.
  - `Low`: Logs the incident for future review and tracking.
- **Web Dashboard**: An interactive, FastAPI-served dashboard to view live incidents, threat levels, and detailed logs.

## 🏗️ Architecture Layers
1. **Pre-Filter (`app/pre_filter.py`)**: Acts as the gatekeeper, quickly identifying suspicious activity with zero API overhead.
2. **Detector (`app/detector.py`)**: Connects to OpenAI to analyze suspicious logs and returns structured JSON threat intel.
3. **Response Handler (`app/response_handler.py`)**: Takes actionable steps based on the AI's classification and logs it to the database.
4. **Database (`app/database.py`)**: SQLite database storing persistent incident records.

## 🛠️ Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Jacky1366/sentinel-soc.git
   cd sentinel-soc
   ```

2. **Install dependencies:**
   Make sure you have Python installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   Create a `.env` file in the root directory and add your OpenAI API key so the AI Analyst layer can function:
   ```env
   OPENAI_API_KEY=your_openai_api_key_here
   ```

4. **Run the application:**
   You can start the FastAPI server using Uvicorn:
   ```bash
   uvicorn app.main:app --reload
   ```

5. **Access the Dashboard:**
   Open your browser and navigate to `http://127.0.0.1:8000/`.

## 🎯 Testing & Simulation
You can use the provided demo script to generate fake attack logs and test the SOC's real-time detection capabilities:
```bash
bash "tests/Demo attack script.sh"
```
You can also run the Python test suite to verify the rule engine's accuracy:
```bash
pytest
```
