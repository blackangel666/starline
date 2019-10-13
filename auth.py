#!/usr/bin/python3
import logging
import requests
import hashlib

def get_app_code(sid_url, app_id, app_secret):
    """
    Получение кода приложения для дальнейшего получения токена.
    Идентификатор приложения и пароль выдаются контактным лицом СтарЛайн.
    :param sid_url: URL StarLineID сервера
    :param app_id: Идентификатор приложения
    :param app_secret: Пароль приложения
    :return: Код, необходимый для получения токена приложения
    """
    url = sid_url + 'application/getCode/'
    logging.info('execute request: {}'.format(url))

    payload = {
        'appId': app_id,
        'secret': hashlib.md5(app_secret.encode('utf-8')).hexdigest()
    }
    r = requests.get(url, params=payload)
    response = r.json()
    logging.info('response info: {}'.format(r))
    logging.info('response data: {}'.format(response))
    if int(response['state']) == 1:
        return response['desc']['code']
    raise Exception(response)

def get_app_token(sid_url, app_id, app_secret, app_code):
    """
    Получение токена приложения для дальнейшей авторизации.
    Время жизни токена приложения - 4 часа.
    Идентификатор приложения и пароль выдаются контактным лицом СтарЛайн.
    :param sid_url: URL StarLineID сервера
    :param app_id: Идентификатор приложения
    :param app_secret: Пароль приложения
    :param app_code: Код приложения
    :return: Токен приложения
    """
    url = sid_url + 'application/getToken/'
    logging.info('execute request: {}'.format(url))
    payload = {
        'appId': app_id,
        'secret': hashlib.md5((app_secret + app_code).encode('utf-8')).hexdigest()
    }
    r = requests.get(url, params=payload)
    response = r.json()
    logging.info('response info: {}'.format(r))
    logging.info('response data: {}'.format(response))
    if int(response['state']) == 1:
        return response['desc']['token']
    raise Exception(response)

def get_slid_user_token(sid_url, app_token, user_login, user_password):
    """
     Аутентификация пользователя по логину и паролю.
     Неверные данные авторизации или слишком частое выполнение запроса авторизации с одного
     ip-адреса может привести к запросу капчи.
     Для того, чтобы сервер SLID корректно обрабатывал клиентский IP,
     необходимо проксировать его в параметре user_ip.
     В противном случае все запросы авторизации будут фиксироваться для IP-адреса сервера приложения, что приведет к частому требованию капчи.
    :param sid_url: URL StarLineID сервера
    :param app_token: Токен приложения
    :param user_login: Логин пользователя
    :param user_password: Пароль пользователя
    :return: Токен, необходимый для работы с данными пользователя. Данный токен потребуется для авторизации на StarLine API сервере.
    """
    url = sid_url + 'user/login/'
    logging.info('execute request: {}'.format(url))
    payload = {
        'token': app_token
    }
    data = {}
    data["login"] = user_login
    data["pass"] = hashlib.sha1(user_password.encode('utf-8')).hexdigest()
    r = requests.post(url, params=payload, data=data)
    response = r.json()
    logging.info('response info: {}'.format(r))
    logging.info('response data: {}'.format(response))
    if int(response['state']) == 1:
        return response['desc']['user_token']
    raise Exception(response)

def slapi_auth(slapi_url, slid_token):
    """
    Авторизация пользователя по токену StarLineID. Токен авторизации предварительно необходимо получить на сервере StarLineID.
    :param slapi_url:   URL StarLineAPI сервера
    :param slid_token: Токен StarLineID
    :return: Токен пользователя на StarLineAPI
    """
    url = slapi_url + 'json/v2/auth.slid'
    logging.info('execute request: {}'.format(url))
    data = {
        'slid_token': slid_token
    }
    r = requests.post(url, json=data)
    response = r.json()
    logging.info('response info: {}'.format(r))
    logging.info('response data: {}'.format(response))
    return r.cookies["slnet"]

def main():
    ### Входные данные ###
    app_secret = "123456789"       # Пароль приложения
    app_id = 15                                           # ID приложения
    login = "1234567890"                         # Логин аккаунта
    password = "123456789"                                 # Пароль аккаунта
    sid_url = 'https://branch-x96-id.starline.ru/apiV3/'  # URL StarLineID сервера
    slapi_url = 'https://branch-x96-slnet.starline.ru/'   # URL StarLineAPI сервера


    ### Прохождение аутентификации в системе StarLine ####
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    # Получим код приложения
    app_code = get_app_code(sid_url, app_id, app_secret)

    # Получим токен приложения. Действителен 4 часа
    app_token = get_app_token(sid_url, app_id, app_secret, app_code)

    # Получим slid-токен юзера. Действителен 1 год
    slid_token = get_slid_user_token(sid_url, app_token, login, password)
    logging.info('SLID token: {}'.format(slid_token))

    # Пройдем авторизацию на StarLineAPI сервере
    # С полученным токеном можно обращаться к API-метода сервера StarLineAPI
    # Токен действителен 24 часа
    slnet_token = slapi_auth(slapi_url, slid_token)
    logging.info('slnet token: {}'.format(slnet_token))
    logging.info('ok.')

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(e)
