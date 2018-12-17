from resource_server.oauth_security import OAuthSecurity
from oauth2_server.app import create_app


app = create_app('BaseConfig')


# Run on network with 'python app.py'
if __name__ == "__main__":
    app.run(threaded=True, host='0.0.0.0', port=app.config['PORT'])
