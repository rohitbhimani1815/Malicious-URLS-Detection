from django.shortcuts import render
import csv
from keras.models import model_from_json
import json
from proj.whois_data import fun_whois

# import pyrebase
from pymongo import MongoClient
import datetime
from django.http import JsonResponse
from keras.preprocessing import sequence
from string import printable
import warnings

warnings.filterwarnings("ignore")

# config = {
#     'apiKey': "AIzaSyBSyiGygAJST4sfy2vKnakRkwlRDNWzKus",
#     'authDomain': "siht20.firebaseapp.com",
#     'databaseURL': "https://siht20.firebaseio.com",
#     'projectId': "siht20",
#     'storageBucket': "siht20.appspot.com",
#     'messagingSenderId': "1051406150301",
#     'appId': "1:1051406150301:web:77571113ba1452007dc274",
#     'measurementId': "G-VN0Y1F08EK"
#   }

# firebase = pyrebase.initialize_app(config)
# auth = firebase.auth()
# db = firebase.database()


def load_model_LSTM():
    with open(r"proj\files\data1DConvLSTM.json", "r") as f:
        model_json = json.load(f)
        model = model_from_json(model_json)
    model.load_weights(r"proj\files\data1DConvLSTM.h5")
    return model


LSTM = load_model_LSTM()


def upload(request):
    return render(request, "upload.html")


def post_upload(request):
    csv_file = request.FILES.get("csv_file")
    decoded_file = csv_file.read().decode("utf-8").splitlines()
    reader = csv.DictReader(decoded_file)

    client = MongoClient(
        "mongodb+srv://abhip1912:abcd1234@cluster0.ywymp.mongodb.net/<dbname>?retryWrites=true&w=majority"
    )
    db = client.get_database("Demo")
    records = db.Blacklist

    # for row in reader:
    #     data ={ 'url': row.get('url'), 'lable': row.get('lable') }
    #     print(str(data))
    #     db.child('urls').child(counter).set(data)
    #     counter += 1

    # for row in reader:
    #     data = {'url':row.get('url')}
    #     db.child('blacklist').child(counter).set(data)
    #     counter += 1

    all_new = []
    counter = 0
    for row in reader:
        data = {"url": row.get("url")}
        all_new.append(data)
        counter += 1
    records.insert_many(all_new)
    return render(request, "upload.html")


def Vector(url):
    max_len = 75
    url_int_tokens = [[printable.index(x) + 1 for x in url if x in printable]]
    X = sequence.pad_sequences(url_int_tokens, maxlen=max_len)
    return X


def predictor(url):
    feature = Vector(url)
    prediction_LSTM = LSTM.predict(feature, batch_size=1)
    if prediction_LSTM < 0.65:
        prediction_LSTM = "Begnine"
    else:
        prediction_LSTM = "Malicious"
    return prediction_LSTM


def home(request):
    if request.method == "POST":
        url_link = request.POST.get("url")
        feed = predictor(url_link)
        print(feed)
        d = fun_whois(url_link)
        d['malicious']=feed
        print(d)
    e = d
    return render(request, "layout.html", {"e": e.items()})


def feedback(request):
    client = MongoClient(
        "mongodb+srv://abhip1912:abcd1234@cluster0.ywymp.mongodb.net/<dbname>?retryWrites=true&w=majority"
    )
    db = client.get_database("Demo")
    records = db.feedback

    name = request.POST["name"]
    email = request.POST["email"]
    msg = request.POST["msg"]
    data = {"name": name, "email": email, "msg": msg}
    records.insert_one(data)
    return render(request, "layout.html")

