import re
import pandas as pd
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from tensorflow.keras.models import load_model
import pickle

# Load the feature information
with open(r"./feature_info.pkl",'rb') as feature_info_file:
    feature_info = pickle.load(feature_info_file)

permissions_list = feature_info["permissions_list"]
api_call_signatures = feature_info["api_call_signatures"]
intents = feature_info["intents"]
commands_signatures = feature_info["keywords"]

# Load the trained model
loaded_model = load_model(r"./trainedmodel.h5")

# Function to process APK file and display risk values
def pred(apk_file_path):
    try:
        # Load APK information 
        a = APK(apk_file_path)
        d = DalvikVMFormat(a.get_dex())
        permissions = a.get_permissions()

        # Process permissions
        found_permissions = []
        for permission in permissions:
            permission = permission.split(".")[-1]
            if permission in permissions_list:
                found_permissions.append(permission)

        # Process API call signatures
        found_api_signatures = []
        for method in d.get_methods():
            for api_call in api_call_signatures:
                if re.search(api_call, method.get_descriptor()):
                    found_api_signatures.append(api_call)

        # logic to extract intents using androguard or other methods
        found_intents = []
        #for service in a.get_services():
            #intent_actions = service.get_intent_filters("action")
            #found_intents.extend(intent_actions)

        # logic to extract commands signatures using androguard or other methods
        found_commands_signatures = []
        #for method in d.get_methods():
            #if "executeCommand" in method.get_code().get_output():
                #found_commands_signatures.append("executeCommand")

        # Create a DataFrame for testing
        test_df = pd.DataFrame(columns=["filename"])

        # Set the filename in the DataFrame
        test_df.loc[0, "filename"] = apk_file_path

        # Set permission columns in the DataFrame
        for permission in permissions_list:
            test_df[permission] = 1 if permission in found_permissions else 0

        # Set API call signature columns in the DataFrame
        for api_call in api_call_signatures:
            test_df[api_call] = 1 if api_call in found_api_signatures else 0

        # Set intent columns in the DataFrame
        for intent in intents:
            test_df[intent] = 1 if intent in found_intents else 0

        # Set commands signature columns in the DataFrame
        for command_signature in commands_signatures:
            test_df[command_signature] = 1 if command_signature in found_commands_signatures else 0

        # Drop the "filename" column
        test_data = test_df.drop("filename", axis=1)

        # Display the risk values for each feature as percentages
        print("Risk values for features:")
        for feature in test_data.columns:
            if feature != 'filename':  # Skip the filename column
                risk_value = test_data[feature].values[0] * 100  # Convert binary values to percentages
                print(f"{feature}: {risk_value:.2f}%")

        # Predict using the deep learning model
        prediction = loaded_model.predict(test_data)

        # Assuming your model output is a probability distribution (categorical)
        # Check if the predicted probability is near malicious, risk, or safe
        if prediction > 0.1:
            prediction="Malicious"
        else:
            prediction="Safe"
            
        return prediction

    except Exception as e:
        print(f"Error processing APK file: {e}")
        print(f"The problematic attribute is: {e.args[0]}")

#Input APK file path until 'exit' is provided
#while True:
 #   apk_file_path = input("Enter the path to the APK file (or type 'exit' to quit): ")
 #   if apk_file_path.lower() == 'exit':
  #      break
   # else:
    #    pred(apk_file_path)
