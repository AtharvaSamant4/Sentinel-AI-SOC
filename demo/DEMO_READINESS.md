# SENTINEL Demo Readiness

## 1. Demo Script (STRICT)

### Intro (10 sec)
"This is SENTINEL, a real-time AI-SOC that detects, explains, and responds to threats autonomously."

### Attack Trigger (10 sec)
"I will launch a controlled brute-force attack from the dashboard control panel now."

### Detection Explanation (20 sec)
"You can see live logs turning red, anomaly volume spiking, and threat cards appearing in risk order."

### AI Analysis (20 sec)
"The analyst panel explains what is happening, why it matters, attacker intent, and immediate mitigations."

### Response + Control (20 sec)
"SENTINEL automatically blocks and flags sources, locks accounts when needed, and creates audited response actions."

### Closing (10 sec)
"This is not just detection. It is an end-to-end SOC story from telemetry to autonomous containment."

## 2. Backup Demo Plan

1. Play pre-recorded 60-90 second walkthrough video from local disk.
2. Show static screenshots from demo/backup if live network is unstable.
3. Use scripted trigger sequence:
   - bruteforce
   - portscan
   - phishing

## 3. Recording Checklist

1. Start backend and dashboard.
2. Ensure websocket shows live normal traffic first.
3. Trigger brute force and wait until queue/analyst/actions are visible.
4. Trigger phishing and show CRITICAL path and quarantine response.
5. Save final recording as: demo/backup/sentinel-demo.mp4

## 4. Screenshot Checklist

1. Dashboard normal flow: demo/backup/01-normal.png
2. Attack spike + red stream: demo/backup/02-spike.png
3. AI analysis + actions visible: demo/backup/03-analysis-response.png
