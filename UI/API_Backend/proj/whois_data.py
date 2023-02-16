import whois
from urllib import parse


def fun_whois(url):
    url = parse.unquote_plus(url.strip())
    if not parse.urlparse(url.strip()).scheme:
        url = "http://" + url
    data = parse.urlparse(url.strip())
    host = data.netloc
    try:
        whois_obj = whois.whois(host)
        li = [
            "organization",
            "domain_name",
            "name_servers",
            "country",
            "state",
            "updated_date",
            "creation_date",
            "expiration_date",
        ]
        dict1 = {
            "organization": None,
            "domain_name": None,
            "name_servers": None,
            "country": None,
            "state": None,
            "updated_date": None,
            "creation_date": None,
            "expiration_date": None,
        }
        for i in li:
            if i == "updated_date" or i == "creation_date" or i == "expiration_date":
                try:
                    dict1[i] = whois_obj[i].strftime("%m/%d/%Y")
                except:
                    continue
            else:
                dict1[i] = whois_obj.get(i, None)
    except:
        dict1 = {
            "organization": None,
            "domain_name": None,
            "name_servers": None,
            "country": None,
            "state": None,
            "updated_date": None,
            "creation_date": None,
            "expiration_date": None,
        }
    return dict1
