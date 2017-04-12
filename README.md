# Travel Blog

### What is this?
This is a data driven web application which does the followings:
* There are multiple categories of tourist places, each containing multiple places.
* Users can write blogs on places. They can modify or delete their blogs.
* Images can also be uploaded in blogs and can be edited and deleted.
* It has protection for cross site request forgery.

### How to use it?
* Download the project from github. In the command propmt, after going into desired directory type 
* It can be run in virtual machine using vagrant for file sharing. To know more on how to use these, have 
a look here: 'https://www.vagrantup.com/intro/getting-started/'
* After going into vagrant, launch the web application in localhost using 
> python travel.py
* Open localhost:5000 in the brower.
* Users can login using their Google and Facebook accounts.
* Functionalities like adding a place, posting/editing/deleting blogs are allowed only for logged in users and
only for their own blogs.
