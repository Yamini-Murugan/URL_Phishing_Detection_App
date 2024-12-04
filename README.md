# Development and Performance Evaluation of a Dockerized Flask Application for Phishing URL Detection Across AWS and Azure


## Objective

Phishing, a prevalent cybersecurity threat responsible for numerous data breaches affecting individuals and businesses worldwide, necessitates the need to develop an efficient detection system. This project builds a Phishing URL detection application utilizing advanced Deep Learning models and deployed on multi-cloud environments. The aim of this research is to build a dockerized flask application and evaluate its performances across AWS and Azure by leveraging cloud-native monitoring tools.


## Data Collection

The dataset used for this experiment was obtained for Kaggle, https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset - a collection of a huge dataset of 651,191 URLs, out of which 428103 benign or safe URLs, 96457 defacement URLs, 94111 phishing URLs, and 32520 malware URLs. This Research work uses 5000 benign and Phishing URLs for training the Deep Learning Models.


## Feature Extraction

Here 19 features and 1 label feature are extracted from URLs to build a labelled dataset for Deep learning.

The category of features extracted from the URL data are as follows:

1.   Address Bar based Features - This Category has 9 features extracted namely;

          1.	Domain Of URL 
          2.	IP Address in URL  
          3.	Having @ Symbol in URL 
          4.	Length of URL  
          5.	Depth if URL 
          6.	Redirection ‘//’ in URL 
          7.	‘http/https’ in Domain name 
          8.	Using URL Shortening Services (TinyURL)
          9.	Prefix or Suffic ‘-‘ in Domain 
        
3.   Domain based Features - This Category has 4 features extracted namely;
   
          10. DNS Record  
          11. Website Traffic
          12. Age of Domain
          13. End Period of Domain

5.   HTML & Javascript based Features- This Category has 6 features extracted namely;
   
          14.	Iframe Redirection 
          15.	Status Bar Customization 
          16.	Disabling Right Click 
          17.	Website Forwarding
          18.	LinksPointingToPage 
          19.	GoogleIndex 

The dataset used in this study is categorised as a classification problem where the input URL is classified as phishing (1) or benign (0) labels throughout.

*The logic pertaining to these feature extraction is present in the python file urlfeatureextraction.py*

## Models & Training

Deep Learning models are chosen for this study based on their ability to adapt and automatically learn complex patterns in data.
The Modles considered to train the dataset in this project are:

* CNN - Convolutional Neural Network
* LSTM - Long Short-Term Memory
* BILSTM - Bidirectional LSTM 

*The logic pertaining to Deep Learning Model training is shared in the below Colab link*

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/drive/1xxv0iOEGdy_iIUQ4RsqQGj1yt9UPicd9?usp=drive_open)

The Feature Extracted *final_dataframe* from dataset folder is used to train the above deep learning models and the BILSTM - Bidirectional LSTM with high accuracy is chosen to be used in the flask application to detect phisishing URL effectively.

## Dockerized Flask Application 

The Phishing URL detection Application is built by importing flask web application framework, the front end details are enclosed in index.html and sevices.html files, the logic for triggering the user input for URL entry is present in app.py

This Flask app is then containerized using docker, the image set up configuration code is present in the Dockerfile.

## Cloud Deployment 

The dockerized image is then deploy on cloud using AWS Elastic Beanstalk and Azure Container Apps to compare the performance metrics 

