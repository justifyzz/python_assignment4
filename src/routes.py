from flask import render_template, url_for, flash, redirect, request
from datetime import datetime, timedelta
from flaskweb.forms import RegistrationForm, LoginForm, CheckForm
from flaskweb.models import User, Articles
from flaskweb import app, db, bcrypt
from flask_login import login_user, current_user, logout_user
import jwt
from bs4 import BeautifulSoup as soup
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/reg', methods=['GET', 'POST'])
def reg():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashes_psw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        token = jwt.encode({'user': form.email.data, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        user = User(username=form.username.data, email=form.email.data, password=hashes_psw, token=token)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been create. Please log in!', 'success')
        return redirect(url_for('index'))
    return render_template('reg.html', title='Register', form=form)


@app.route('/log', methods=['GET', 'POST'])
def log():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            token = jwt.encode({'user': form.email.data, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                               app.config['SECRET_KEY'])
            user.token = token
            db.session.add(user)
            db.session.commit()
            flash(f'Login successful. Welcome, {user.username}', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful, please check email and password', 'danger')
    return render_template('log.html', title="Login", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/protected')
def protected():
    token = request.args.get('token')
    user = User.query.filter_by(token=token).first()
    if user:
        return '<h1>The token has been verified {}</h1>'.format(token)
    return '<h1>Could not verify your token</h1>'


@app.route('/coin', methods=['GET', 'POST'])
def coin():
    form = CheckForm()

    headerArr = []
    paragraphArr = []
    imgArr = []

    if form.validate_on_submit():
        # Scrapper

        cryptoName = (str(form.crypto_name.data)).lower()

        url = 'https://coinmarketcap.com/currencies/' + cryptoName + '/news/'

        driver = webdriver.Chrome(ChromeDriverManager().install())
        driver.get(url)

        page = driver.page_source
        page_soup = soup(page, 'html.parser')

        headers = page_soup.findAll("h3", {"class": "sc-1q9q90x-0", "class": "gEZmSc"})
        paragraphs = page_soup.findAll("p", {"class": "sc-1eb5slv-0", "class": "svowul-3", "class": "ddtKCV"})
        img_div = page_soup.findAll("div", {"class": "svowul-5", "class": "czQlor"})

        exists = check(cryptoName)

        for i in range(0, min(len(headers), len(paragraphs))):
            header = headers[i].text.strip()
            paragraph = paragraphs[i].text.strip()
            src = img_div[i].find('img')
            img = src.attrs['src']

            if not exists and len(header) > 0 and len(paragraph) > 0:
                new_article = Articles(f'{cryptoName}', f'{header}', f'{paragraph}', f'{img}')
                db.session.add(new_article)
                db.session.commit()

        for row in db.session.query(Articles).filter_by(crypto_name=cryptoName):
            headerArr.append(row.header)
            paragraphArr.append(row.paragraph)
            imgArr.append(row.img)

        if len(headerArr) != 0:
            flash(f'Successfully pulled {form.crypto_name.data}!', 'success')
        else:
            flash(f'Couldn\'t find {form.crypto_name.data}!', 'warning')

    return render_template('coin.html', title='Check', form=form, headerArr=headerArr, paragraphArr=paragraphArr,
                           imgArr=imgArr)


def check(cryptoName):
    for row in db.session.query(Articles).filter_by(crypto_name=cryptoName):
        if row.crypto_name == cryptoName:
            return True
    return False
