from flask import Flask, render_template, g, request, session, redirect, url_for
from database import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import os  # To generate random string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # 24 letter random string


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def get_current_user():
    """
    Function which will return None if no user is logged in,
    else it returns a dictionary containing info about currently
    logged in user. Info contains - id, name, password, expert bit,
    and admin bit.
    :return:
    """
    user_result = None

    if 'user' in session:
        user = session['user']
        db = get_db()
        user_cur = db.execute('select id, name, password, expert, admin from users where name = ?',
                              [user])  # Cursor pointing to row where name matches the name submitted in the form
        user_result = user_cur.fetchone()

    return user_result


@app.route('/')
def index():
    """
    At home page, we want to show the list of questions which have been answered.
    Each question which has been asked should contain asker's name, expert's name,
    question text.
    :return:
    """

    user = get_current_user()
    db = get_db()

    questions_cur = db.execute('''select 
                                    questions.id as question_id, 
                                    questions.question_text, 
                                    askers.name as asker_name, 
                                    experts.name as expert_name 
                                    from questions 
                                    join users as askers on askers.id = questions.asked_by_id 
                                    join users as experts on experts.id = questions.expert_id 
                                    where questions.answer_text is not null''')
    questions_result = questions_cur.fetchall() # dictionary of all such questions
    return render_template('home.html', user=user, questions=questions_result)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    If user wants to register to the site, so there is a form, if user doesnt submit it then
    it is simply a GET request, and if a user submits the form, then we have a POST request.
    We will do the tasks accordingly and notice that since we have two types of requests,
    I had to pass methods attribute to my route to enable them.
    :return:
    """

    user = get_current_user()
    if request.method == "POST":
        """
        So, now we want to insert a new user into the database and all the info such as
        name, password we have it in the request.form thingy (list) as we used the name 
        attribute in the html to reference it while submitting form.
        Update - if a user already exists with given username, then we do not want
        him to register. So, for that- we check whether any dictionary exists with
        submitted user name in our database. If it is not none, then we again send back to
        register page and show an error message that user already exists. 
        """

        db = get_db()
        existing_user_cur = db.execute('select id from users where name = ?', [request.form['name']])   # querying db with given user name.
        existing_user = existing_user_cur.fetchone() # Get the dictionary.
        if existing_user:   # If exists then register back with error message

            return render_template('register.html', user=user, error="User already exists")

        hashed_password = generate_password_hash(request.form['password'], method='sha256') \
            # Function to generate a hashed password so that no one can copy it easily in case database breaks, so sha256 method is used
        db.execute('insert into users (name, password, expert, admin) values(?,?,?,?)',
                   [request.form['name'], hashed_password, '0', '0'])
        db.commit()
        session['user'] = request.form['name']

        return redirect(url_for('index'))

    return render_template('register.html', user=user)


@app.route('/login', methods=['POST', 'GET'])
def login():
    """
    Check whether user name and password entered is correct or not.
    If we have a POST request that is the form is submitted by the
    user and we have to query the database to find the user in the
    database.
    :return:
    """

    user = get_current_user()
    error = None
    if request.method == 'POST':

        db = get_db()
        name = request.form['name']  # Submitted name
        password = request.form['password']  # Submitted password
        user_cur = db.execute('select id,name, password from users where name = ?',
                              [name])  # Cursor pointing to row where name matches the name submitted in the form
        user_result = user_cur.fetchone()
        """ Fetch only one as only one user will exist with given name, i mean we want it
            and return type is a dictionary with keys as name of columns and values as data stored in dictionary.
            Now, we have info about user from database in form of dictionary in user_result and we also have
            the submitted data in the form. We will compare them to check whether password entered is 
            correct or not. 
            check_password_hash() takes in two params, param1 is actually a hash and param2 is a value
            if hash of this value (param2) is same as param1, return true, else return false
        """
        if user_result:
            if check_password_hash(user_result['password'], password):
                session['user'] = user_result['name']
                # if password is correct, login , and then back to home page.
                return redirect(url_for('index'))
            else:
                error = "The password is Incorrect"
        else :
            error = "Username is Incorrect"

    return render_template('login.html', user=user, error=error)


@app.route('/question/<question_id>')
def question(question_id):
    """
    This route shows a particular questions, for that we need an id of
    the question. For showing that particular question, we need text
    of question and answer, asker's name and expert's name who answered it.
    :param question_id:
    :return:
    """
    user = get_current_user()
    db = get_db()
    questions_cur = db.execute('''select 
                                    questions.question_text, 
                                    questions.answer_text, 
                                    askers.name as asker_name, 
                                    experts.name as expert_name 
                                from questions 
                                join users as askers on askers.id = questions.asked_by_id 
                                join users as experts on experts.id = questions.expert_id 
                                where questions.id is ?''', [question_id])

    question = questions_cur.fetchone()
    return render_template('question.html', user=user, question=question)


@app.route('/answer/<question_id>', methods=['POST', 'GET'])
def answer(question_id):
    """
    This method is for the expert to answer some questions,
    which are asked to him, he should be able to click
    on a question, answer that question and that
    question should be removed from his list and
    should be displayed on the home page.
    :param question_id:
    :return:
    """
    user = get_current_user()
    db = get_db()
    if not user:
        return redirect(url_for('login'))

    if user['expert'] == 0:
        return redirect(url_for('index'))

    if request.method == 'POST':
        """
        If the expert, that is current user posts an answer,
        then we have to update the database, that this 
        answer is not null now, so that this is not displayed. 
        """
        db.execute('update questions set answer_text = ? where id = ?',
                   [request.form['answer'], question_id])
        db.commit()
        return redirect(url_for('unanswered'))

    """
    If it is a Get request then we have to show unanswered questions 
    to the expert, first of all we fetch that question, whose id is
    passed in the link and show that question.
    """
    question_cur = db.execute('select id, question_text from questions where id = ?', [question_id])
    question = question_cur.fetchone()
    return render_template('answer.html', user=user, question=question)


@app.route('/ask', methods=['POST', 'GET'])
def ask():
    """
    This function is for the ask page where a user will type in a
    question and select which expert to answer. So, two things are
    submitted in the form. Now, we have to add this data to database.
    Add this to questions table,
    :return:
    """
    user = get_current_user()
    db = get_db()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        """
        Post request implies that form has been submitted, so we
        insert this question to the database along with, id of
        user who asked it, and to which expert he asked this
        question.
        """
        db.execute('insert into questions (question_text, asked_by_id, expert_id) values (?,?,?)',
                   [request.form['question'], user['id'], request.form['expert']])
        db.commit()
        return redirect(url_for('index'))

    """
    If it is a Get request then we show that form where a question can 
    be asked by the user and he has to choose among a list of experts.
    Since, these experts are from database, we need to fetch them,
    ans pass all such experts in form of dictionary to ask.html page,
    so that we can show that list of users.
    """
    expert_cur = db.execute('select id, name from users where expert =1')
    expert_results = expert_cur.fetchall()

    return render_template('ask.html', user=user, experts=expert_results)


@app.route('/unanswered')
def unanswered():
    """
    view all the unanswered questions for this expert,
    query for database where for all questions
    whose answer is no and expert id is same as that
    expert who is logged in.
    :return:
    """

    user = get_current_user()
    db = get_db()
    if not user:
        return redirect(url_for('login'))

    if user['expert'] == 0:
        return redirect(url_for('index'))

    """
    Now, from database we need those questions, which are not answered by
    current user, that is an expert. We need id of the questions, the 
    text, and also name of the user, so we have to join the table 
    """
    questions_cur = db.execute('''select 
                                    questions.id, 
                                    questions.question_text, 
                                    users.name from questions 
                                    join users on users.id = questions.asked_by_id 
                                    where questions.answer_text is null and questions.expert_id = ?''',
                                    [user['id']])
    questions = questions_cur.fetchall()
    return render_template('unanswered.html', user=user, questions=questions)


@app.route('/users')
def users():
    """
    For admin to see all users, we fetch all users and
    send a list of dictionaries to users.html.
    :return:
    """

    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    users_cur = db.execute('select id, name, expert, admin from users')
    users_results = users_cur.fetchall()
    return render_template('users.html', user=user, users=users_results)


@app.route('/promote/<user_id>')
def promote(user_id):
    """
    To promote user to expert, we pass user_id as a param
    so as to know which user is to be made an expert now,
    after that execute one db operation to set expert
    bit as 1 for given user_id.
    :param user_id:
    :return:
    """
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()
    db.execute('update users set expert = 1 where id =?', [user_id])
    db.commit()
    return redirect(url_for('users'))  # return back to users and change can be seen.


@app.route('/logout')
def logout():
    """
    To logout user from a session
    :return:
    """

    user = get_current_user()

    session.pop('user', None)
    return redirect(url_for('index'))  # Back to home page after logging out


if __name__ == '__main__':
    app.run(debug=True)
