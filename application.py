# Importing required libraries
import numpy as np
import pandas as pd
import tensorflow as tf
from urlfeatureextraction import * # module for extracting features from URLs
from flask import Flask, request, render_template
from tensorflow.keras.models import load_model # load the pre-trained model

# Extrated features of the URL
feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
    'Domain_Age', 'Domain_End','IframeRedirection','StatusBarCust','DisableRightClick','WebsiteForwarding',
    'LinksPointingToPage', 'GoogleIndex']

# loading the saved model
bilstm_model = load_model('./Saved_Best_Model/bilstm_model.h5')

# Initializing the Flask application
application = Flask(__name__)
app=application


# Route to render the main index page

@app.route('/')
def index(): 
  return render_template('index.html')

# Route to render the homepage (duplicate of index)
@app.route('/homepage')
def homepage(): 
  return render_template('index.html')

# Route to render the service page
@app.route('/servicepage')
def servicepage(): 
  return render_template('services.html')

# Route to handle URL detection

@app.route('/urldetection', methods=['POST'])

def urldetection():
  #Input Handling from the form submitted by the user
  url = request.form["url"]
  #Feature Extraction
  datalist = urlfeature_extractor(url) #function to extract features from the submitted URL.
  #Dataframe Creation
  dataframe = pd.DataFrame([datalist], columns= feature_names) 
  #print(dataframe)
  # Data Preprocessing
  dataframe.drop(['Domain'], axis='columns', inplace=True)
  dataframe = np.array(dataframe)
  dataframe = np.expand_dims(dataframe, axis=2)
  print(dataframe)
  # Prediction
  ypred = bilstm_model.predict(dataframe)
  # Finding the index of the maximum value with axis 1 
  ypred = np.argmax(ypred,axis=1) #class label with the highest predicted probability
  outputres = ypred[0]

  # Output 
  if outputres == 1:
    outputres = "ALERT URL DETECTED AS PHISHING !"

  else:
    outputres = "URL DETECTED AS SAFE !"
  # Displaying the Output / prediction result on the services.html page 
  return render_template('services.html', res2 = outputres, inpurl = url)

# Running the Flask app in non-debug mode
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)