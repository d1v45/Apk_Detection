# APK Maliciousness Prediction and Analysis Tool

This project is a web-based tool designed to scan and analyze APK files for potential malicious behavior using machine learning and traditional virus scanning engines. It combines the power of multiple techniques, including the VirusTotal API, machine learning models, and static APK analysis, to detect malicious apps.

## Overview

The tool processes APK files to identify malicious features such as suspicious permissions, API calls, intents, and command signatures. It integrates multiple components:

- **Flask backend**: Handles the file upload, integrates with external APIs (like VirusTotal), and invokes the machine learning model for APK analysis.
- **Machine learning model**: A trained neural network model used to predict whether an APK is malicious or safe based on certain features extracted from the APK.
- **Frontend**: A simple web interface for users to upload APK files and receive detailed analysis results.
- **VirusTotal Integration**: Uses the VirusTotal API to check for APK file results from various security engines.

## Features

- **File Upload**: Upload APK files directly to the web interface for analysis.
- **Machine Learning Model**: Predicts if an APK is malicious based on features extracted from the APK using a deep learning model.
- **VirusTotal Integration**: Checks the APK file against over 20 antivirus engines using the VirusTotal API.
- **Results Dashboard**: Displays both the results of the VirusTotal scan and the machine learning model prediction in a user-friendly format.
- **Maliciousness Alerts**: Provides alerts and messages based on whether the APK is flagged as malicious by the VirusTotal scan and/or the machine learning model.

## Tech Stack

- **Frontend**: HTML, JavaScript (Vanilla), CSS
- **Backend**: Python (Flask)
- **Machine Learning**: TensorFlow, Keras
- **Static APK Analysis**: Androguard
- **Database**: None (temporary storage for uploaded files)
- **External API**: VirusTotal API (for additional virus scanning)
- **Environment**: Python 3.x

## How It Works

1. **Upload APK**: The user uploads an APK file using the web interface.
2. **Static Analysis**: The Flask backend uses Androguard to analyze the APK, checking permissions, API calls, intents, and command signatures.
3. **VirusTotal API**: The backend also checks the APK hash against VirusTotal to gather results from multiple antivirus engines.
4. **Machine Learning Prediction**: The Flask backend invokes a trained Keras model to predict if the APK is malicious or safe.
5. **Display Results**: The results are displayed on the web interface, with alerts based on the prediction from both VirusTotal and the machine learning model.

## Project Structure

```
vulnerability-scanner/
├── backend/
│   ├── app.py (Flask API)
│   ├── models/
│   │   └── ScanResult.js (MongoDB schema)
│   ├── templates/
│   │   └── index.html (Frontend template)
│   ├── static/
│   └── requirements.txt
├── feature_info.pkl (Feature information for ML model)
├── trainedmodel.h5 (Trained machine learning model)
└── README.md (This file)
```

## Prerequisites

- **Python 3.x**
- **Flask**: For the web framework
- **TensorFlow / Keras**: For the machine learning model
- **Androguard**: For analyzing APK files
- **Requests**: For making API requests to VirusTotal
- **VirusTotal API Key**: You need a VirusTotal API key for scanning files. You can get one by signing up on [VirusTotal](https://www.virustotal.com/).

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/APK-Maliciousness-Prediction.git
   cd APK-Maliciousness-Prediction
   ```

2. **Install the dependencies:**

   You can install the required Python libraries using `pip`. Run the following command:

   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Set up environment variables:**

   In the backend folder, create a `.env` file and add your VirusTotal API key:

   ```bash
   API_KEY=your_virustotal_api_key_here
   ```

4. **Run the Flask application:**

   To start the backend server, run:

   ```bash
   python backend/app.py
   ```

   This will start the Flask server, which you can access via `http://127.0.0.1:5000`.

5. **Access the Frontend:**

   Open a web browser and navigate to `http://127.0.0.1:5000`. You can upload APK files for analysis from the interface.

## How to Use

1. Open the app in your browser.
2. Upload an APK file using the file upload form.
3. Click the "Analyze" button to start the process.
4. Wait for the system to analyze the APK, including checks from the VirusTotal API and the machine learning model.
5. Review the results, including the VirusTotal scan results and the machine learning model prediction (Safe or Malicious).
6. Based on the analysis, alerts or messages will guide you regarding the APK's safety.

## Model Training

The machine learning model is trained using a custom dataset of APK features. This includes:

- **Permissions**: List of permissions required by the app.
- **API Calls**: Specific API calls that may indicate malicious activity.
- **Intents**: Specific intent actions that could be a sign of malicious behavior.
- **Command Signatures**: Indicators of suspicious commands executed by the APK.

If you would like to retrain the model or modify the training process, you can update the `feature_info.pkl` file and retrain the model using the `Testi.py` script.

## Known Issues

- **VirusTotal API Rate Limits**: The VirusTotal API has rate limits. If you have a free account, you may be limited in the number of requests you can make per minute. Consider using a premium API key for more frequent scans.
- **APK Analysis Speed**: APK analysis, especially with Androguard and the VirusTotal API, may take some time depending on the size of the APK and network speed.

## Contributing

We welcome contributions! To contribute, follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit them (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a new Pull Request.
