from flask import Flask, render_template, request, jsonify
import os
from werkzeug.utils import secure_filename
import clnt
import Testi
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv('API_KEY')

app = Flask(__name__,template_folder='./templates')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'apk'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST' and 'apk' in request.files:
        file = request.files['apk']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            result = clnt.analyze_file(file_path, api_key)
            prediction = Testi.pred(file_path)
            messages = analyze_result(result, prediction)

            # Returning JSON response
            return jsonify(result=result, prediction=prediction, messages=messages)

    return render_template('index.html')

def analyze_result(result, prediction):
    messages = []

    if result and result["malicious_count"] > 0 and prediction == "Malicious":
        messages.append('Engine found the given file malicious!')
        messages.append('ML Model Prediction: The application is predicted to be MALICIOUS.')
        # Trigger an alert or alarm here

    elif result and result["malicious_count"] > 0 and prediction == "Safe":
        messages.append(f'{result["malicious_count"]} engine found the given file malicious!')
        messages.append('ML Model Prediction: The application is predicted to be MALICIOUS.')
        # Trigger an alert or alarm here

    elif result and result["malicious_count"] == 0 and prediction == "Safe":
        messages.append('No engine found the given file malicious!')
        messages.append('ML Model Prediction: The application is predicted to be SAFE.')

    return messages

if __name__ == '__main__':
    app.run(debug=True)
