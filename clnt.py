import requests
import json
import colorama
from time import sleep
import sys
import hashlib
import Testi
colorama.init()

def type(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def analyze_file(file_path, api_key):
    try:
        # Calculate the hash of the file (SHA-256 in this case)
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        file_hash = sha256_hash.hexdigest()

        # Check the analysis results using the hash
        file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        headers = {"accept": "application/json", "x-apikey": api_key}

        response = requests.get(file_url, headers=headers)
        response.raise_for_status()  # Check for HTTP errors

        report = response.json()

        # Extract relevant information from the report
        name = report.get("data", {}).get("attributes", {}).get("meaningful_name", "Unable to fetch")
        hash_value = report.get("data", {}).get("attributes", {}).get("sha256", "")
        descp = report.get("data", {}).get("attributes", {}).get("type_description", "")
        size = report.get("data", {}).get("attributes", {}).get("size", 0) * 10**-3
        result = report.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        scan_date = report.get("data", {}).get("attributes", {}).get("last_analysis_date", "")
        positives = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        total_scans = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("total", 0)
        permalink = report.get("data", {}).get("attributes", {}).get("permalink", "")
        verbose_msg = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("verbose_msg", "")
        malicious_count = sum(1 for verdict in result.values() if verdict.get("category") == "malicious")
        

        if malicious_count != 0:
            if malicious_count > 20:
                res = "Malicious"
            else:
                res = "Safe"
            
        elif malicious_count == 0:
            res = "Safe"
        
        # Return the analysis results as a dictionary
        analysis_result = {
            "res": res,
            "name": name,
            "hash_value": hash_value,
            "size": size,
            "totalscans": total_scans,
            "description":descp,
            "positives": positives,
            "result": result,
            "scan_date": scan_date,
            "verbose_msg": verbose_msg,
            "malicious_count":malicious_count
            # Add other values as needed
        }

        return analysis_result
    
    except requests.exceptions.RequestException as e:
        print(colorama.Fore.RED + f"Error: {e}")
        return {"error": f"Error: {e}"}
    except ValueError as e:
        print(colorama.Fore.RED + f"Error: {e}")
        return {"error": f"Error: {e}"}

# Example usage
api_key = "c0910e2ea494def5b9f0d98041a816e4fa7a551aeb6786826bfeb0352db259d5"
#while True:
   ## file_path = input("Enter the path to the APK file (or type 'exit' to quit): ")
    #if file_path.lower() == 'exit':
     #   break
# Call the function and store the analysis results
#analysis_result = analyze_file(file_path, api_key)

# Extract values for further use
#malicious_count = sum(1 for verdict in analysis_result["result"].values() if verdict.get("category") == "malicious")

# Compare with ML model prediction (you can replace this with your actual prediction logic)
#prediction = Testi.pred(file_path)

# Check if both analysis and prediction indicate malicious
#if malicious_count != 0 and prediction =="Malicious":
 #   type(colorama.Back.WHITE + colorama.Fore.RED + 'antivirus found the given file malicious !!')
  #  type(colorama.Back.WHITE + colorama.Fore.RED + "ML Model Prediction: The application is predicted to be MALICIOUS.")
    # Trigger an alert or alarm here

# Check if either analysis or prediction indicate malicious
#elif malicious_count != 0 and prediction=="Safe":
 #   type(colorama.Back.WHITE + colorama.Fore.RED + f'\t\t\t\t{malicious_count} antivirus found the given file malicious !!')
  #  type(colorama.Back.WHITE + colorama.Fore.RED + "ML Model Prediction: The application is predicted to be MALICIOUS.")
    # Trigger an alert or alarm here

#elif malicious_count == 0 and prediction =="Safe":
 #   type(colorama.Back.WHITE + colorama.Fore.GREEN + f'\t\t\t\t No antivirus found the given file malicious !!')
  #  type(colorama.Back.WHITE + colorama.Fore.GREEN + "ML Model Prediction: The application is predicted to be SAFE.")