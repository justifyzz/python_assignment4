# assgnment-4-python

## Title: Flask cryptocurrency news app

## Installation
PyPI
1. ```pip install flask``` 
2. ```pip install flask-bcrypt``` 
3. ```pip install flask_login``` 
4. ```pip install flask-SQLalchemy```
5. ```pip install flask-wtf```
6. ```pip install pyJWT``` 
7. ```pip install WTForms``` 

## Usage 
1. To run server. Type in the terminal
```run flask```
Make sure that you are in the same directory as the application is
1. Go to localhost to be able to use application
You can use application by typing to URL route ```localhost``` or ```http://127.0.0.1:5000/```


## Usage Examples 
## There are 6 main routes in the project.

#### Coin route
Fill in the form given in the web page to acces recent news. Form consists of one input label which requires cryptocurrency name to be submited in, afterwards simply press enter on keyboard or click ```submit``` button on the page. The form returns available information, particularly news in accordance of the currency requested from web site 

#### Index route
Home page of the app. Users are being redirected to the index page after sumbmitting registration or log in form correctly. The index page is also available by simply typing 
```forward slash``` after localhost. 
Example:
* http://localhost:5000/
* http://127.0.0.1:5000/

#### Registration route 
Registartion route contains registration form for users with Email, Username, Password and Repeat password fields . After registration went through ```db.add(user)``` command embeded into the app will add user to the database. All the passwords in the database are hashed using ```bcrypt``` hashing. 
Within the registration route there are several validators such as:
* Email validator
* Repeat password validator
* Password and Email length validator
* Username already exist validator
In addition for all user fields in database JWT token field is also used to create account.

#### Log in route
Log in route allows users to enter the app by authentificating them through validation log in form. Log in route also refreshes -JWT token-, which user implements whenever he enters protected page.

#### Log out route
For users to leave the webpage.

#### Protected route
Protected route is used by authentificated user to verify themselves using their token which was created after registration or log in proccess. By adding ```?token=``` and user token aterwards to the route he/she can verify the secure information transmission
