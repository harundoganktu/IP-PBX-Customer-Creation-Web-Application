from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from pymongo import MongoClient
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import datetime
from itsdangerous import URLSafeTimedSerializer
from itsdangerous import SignatureExpired
import pandas as pd
import re
import io
import unidecode

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')
serializer = URLSafeTimedSerializer(app.secret_key)

# MongoDB bağlantı URI'si
uri = 'mongodb+srv://Harun_Netas:*****@cluster0.x9ixa.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
client = MongoClient(uri)

# Veri tabanını seç
db = client['Harun_Netas']

# Koleksiyonu seç
users_collection = db['users']

# Flask-Mail yapılandırması
/*SMTP*/

mail = Mail(app)


# Form işlemleri
@app.route('/', methods=['GET', 'POST'])
def handle_form():
    if request.method == 'POST':
        action = request.form.get('action')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if action == 'register':
            existing_user = users_collection.find_one({"username": username})
            if existing_user is None:
                hashed_password = generate_password_hash(password)
                users_collection.insert_one({
                    "email": email,
                    "username": username,
                    "password": hashed_password
                })
                # E-posta gönderimi
                msg = Message('Hesabınız Başarıyla Oluşturuldu', sender='tool_netas@outlook.com', recipients=[email])
                msg.html = render_template('confirmation_email.html', username=username,year=datetime.datetime.now().year)
                mail.send(msg)
                flash('Başarıyla kayıt oldunuz, giriş yapabilirsiniz!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Bu kullanıcı adı zaten mevcut!', 'danger')

        elif action == 'login':
            user = users_collection.find_one({"username": username})
            if user and check_password_hash(user['password'], password):
                flash('Başarıyla giriş yaptınız!', 'success')
                return redirect(url_for('welcome', username=username, email=email))
            else:
                flash('Hatalı kullanıcı adı veya şifre!', 'danger')

    return render_template('login.html')


@app.route('/welcome/<username>')
def welcome(username):
    user = users_collection.find_one({"username": username})
    if user:
        email = user['email']
        return render_template('welcome.html', username=username, email=email)
    else:
        flash('Kullanıcı bulunamadı!', 'danger')
        return redirect(url_for('login'))

@app.route('/api/change-password', methods=['POST'])
def change_password():
    data = request.json
    username = data.get('username')
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')

    if not username or not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Tüm alanları doldurun.'}), 400

    user = users_collection.find_one({'username': username})
    if not user or not check_password_hash(user['password'], current_password):
        return jsonify({'success': False, 'message': 'Geçerli şifre yanlış.'}), 400

    update_result = users_collection.update_one(
        {'username': username},
        {'$set': {'password': generate_password_hash(new_password)}}
    )

    if update_result.modified_count == 0:
        return jsonify({'success': False, 'message': 'Şifre güncellenmedi.'}), 500

    return jsonify({'success': True, 'message': 'Şifre başarıyla değiştirildi.'})


######################################################################################
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Kullanıcıyı veritabanından email ile bulalım
        user = users_collection.find_one({"email": email})  # MongoDB sorgusu

        if user:
            username = user["username"]  # Kullanıcının adını veritabanından alın

            # Token oluşturma
            token = serializer.dumps(email, salt='password-reset-salt')

            # Şifre sıfırlama bağlantısı oluştur
            reset_url = url_for('reset_with_token', token=token, _external=True)

            # E-posta gönderimi
            msg = Message('Şifre Sıfırlama Bağlantısı', sender='tool_netas@outlook.com', recipients=[email])
            msg.html = render_template('sıfırlama.html', username=username, reset_url=reset_url, year=datetime.datetime.now().year)
            mail.send(msg)

            flash('Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.', 'success')
        else:
            flash('Bu e-posta adresi ile ilişkili bir hesap bulunamadı.', 'danger')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        # Token'ı doğrula ve e-posta adresini al
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # 1 saatlik süre
    except SignatureExpired:
        flash('Token geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('forgot_password'))
    except:
        flash('Geçersiz token.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Şifreler eşleşmiyor.', 'danger')
            return render_template('reset_password.html', token=token)

        # Şifreyi hashleyip veritabanında güncelle
        hashed_password = generate_password_hash(new_password)
        result = users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})

        if result.modified_count > 0:
            flash('Şifreniz başarıyla sıfırlandı.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Şifre sıfırlama sırasında bir sorun oluştu.', 'danger')

    return render_template('reset_password.html', token=token)
##################################################################################
uploaded_file_content = None
self_result = None #->Customer_Name
self_value = None #->Area
self_itemid = None
customer_ = None

@app.route('/pbx', methods=['POST'])
def pbx():
    global uploaded_file_content, twice_ip_value, cli_tespit, customer_, selected_item, VDID, self_result, TEMOSNO, cfo, cfo_cw, IMSRN
    if 'file' in request.files:
        file = request.files['file']
        if file.filename.endswith('.xls') or file.filename.endswith('.xlsx'):
            try:
                # Dosyayı belleğe yükleyelim
                uploaded_file_content = file.read()
                return "Dosya başarıyla yüklendi. Lütfen IP adresini girin.", 200
            except Exception as e:
                return f"Dosya işlenirken bir hata oluştu: {str(e)}", 500
        else:
            return "Lütfen geçerli bir Excel dosyası yükleyin.", 400

    elif 'ip-address' in request.form:
        ip_address = request.form.get('ip-address')
        isbc_area = request.form.get('isbca-area')
        global selected_item
        selected_item = isbc_area
        self_value = str(selected_item[:3].lower())
        if uploaded_file_content is None:
            return Response("Önce bir dosya yüklemeniz gerekiyor.", status=400, mimetype='text/plain')

        try:
            uploaded_file_stream = io.BytesIO(uploaded_file_content)
            musterı_excel = pd.read_excel(uploaded_file_stream)
            musterı_excel[musterı_excel.columns[9]] = musterı_excel[musterı_excel.columns[9]].astype(str)
            matching_rows = musterı_excel[musterı_excel[musterı_excel.columns[9]].str.contains(re.escape(ip_address), na=False)]
            if not matching_rows.empty:
                row = matching_rows.iloc[0]
                global VDID, TEMOSNO, cfo, cfo_cw, IMSRN
                VDID = row.iloc[17]
                IMSRN = row.iloc[53]
                REMOTE = row.iloc[15]
                SGID = row.iloc[17]
                LOCALIP_tcp = row.iloc[40]
                LOCALIP_udp = row.iloc[47]
                UNIRAIIN = row.iloc[17]
                Customer = row.iloc[22]
                TEMOSNO = row.iloc[13]
                TGRPNAME = row.iloc[12]
                SESSİON = row.iloc[26]
                UGMAXCALNUM = row.iloc[14]
                CLI = row.iloc[16]
                callrıght = row.iloc[21]
                twice_ip_adress = row.iloc[32]
                customer_ip = row.iloc[9]
                cfo = row.iloc[23]
                cfo_cw = row.iloc[27]
                code_il = row.iloc[0]
                borc_kapama = row.iloc[33]
                ###################################################
                ##################################################
                ///*** ISBC CONFIGURATION PARAMETER ***///
                    return Response(response_text, status=200, mimetype='text/plain')
            else:
                return Response("IP adresi bulunamadı", status=404, mimetype='text/plain')
        except Exception as e:
            return Response("Bir hata oluştu: " + str(e), status=500, mimetype='text/plain')

    else:
        return Response("Dosya bulunamadı veya IP adresi girilmedi", status=400, mimetype='text/plain')


@app.route('/get_for_cscf', methods=['POST'])
def get_for_cscf():
    global selected_item, VDID, self_result, TEMOSNO, cfo, cfo_cw, IMSRN# Global değişkene erişmek için 'global' anahtar kelimesini kullanın
    ///*** CSCF CONFIGURATION PARAMETER ***///
        return Response(response_text_for_cscf, status=200, mimetype='text/plain')

@app.route('/delete_command_for_sbc', methods=['POST'])
def get_delete():
    global selected_item, VDID# Global değişkene erişmek için 'global' anahtar kelimesini kullanın
    ///*** DELETE SBC CONFIGURATION PARAMETER ***///
        
        return Response(delete_sbc_command, status=200, mimetype='text/plain')

@app.route('/delete_command_for_cscf', methods=['POST'])
def get_delete_cscf():
    global selected_item, VDID# Global değişkene erişmek için 'global' anahtar kelimesini kullanın
    telana_ıd = VDID + 40000
    UNIRAIIN_slave = VDID + 50000
    ///*** DELETE CSCF CONFIGURATION PARAMETER ***///
        return Response(delete_cscf_command, status=200, mimetype='text/plain')

@app.route('/get_customer', methods=['GET'])
def get_customer():
    global customer_ # Global değişkene erişmek için 'global' anahtar kelimesini kullanın
    print(customer_)
    if customer_:  # Eğer Customer doluysa
        return jsonify({'customer': customer_})
    else:
        return jsonify({'customer': ''}), 404


@app.route('/api/logout', methods=['POST'])
def logout():
    # Kullanıcıyı oturumdan çıkarmak için gereken işlemleri yapın
    # Örneğin: session.clear() veya başka bir oturum yönetimi yöntemi
    return render_template('login.html')


@app.route('/login')
def login():
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
