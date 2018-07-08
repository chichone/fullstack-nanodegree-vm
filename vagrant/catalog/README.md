# Simple Catalog App

## Setup

### Clone Repo

Clone this repo somewhere on your own machine

### Install Vagrant

In order to run this app you must first install vagrant on your machine

https://www.vagrantup.com/downloads.html

### Open vagrantfile

Navigate to the vagrantfile in the vagrant directory in this repo and execute ```vagrant up```

### Set up google app for Oauth2 user sign-in

Then you must setup google's oauth2 for this app. To do so log in to google then navigate to https://console.developers.google.com

Then create a new project by clicking select a project then clicking the plus sign.

Once created, then click select a project again and select the project you just created. Then search for the google plus api and click enable. Once enabled set up an Oauth consent screen by first clicking credentials on the left, then Oauth consent screen tab. Once you have the Oauth consent screen saved, create credentials for a web application setting the javascript origin to: http://localhost:5001 and the authorized redirect URI to http://localhost:5001/usercp. Then activate Oauth2 authorization by searching for google+ api again and once found clicking 'TRY THIS API'. Then toggle Oauth 2.0 to 'ON' giving it the scopes for knowing who you are, your email address and your basic profile info. Then navigate back to your dashboard and download the json credentials for your app. Save this as client_secrets.json in the same directory as views.py and models.py of this repo.

### Run Server

Once you have the client_secrets.json saved, run the app by opening the vagrant environment you set up by running vagrant up, then navigate to views.py and execute ```python views.py```

## Using the App

Now open a browser and navigate to http://localhost:5001 and have fun using the app!
