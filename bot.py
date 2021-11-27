
import cherrypy
import os
import sys
import threading
import traceback
import webbrowser
import pickle
from urllib.parse import urlparse
from base64 import b64encode
from fitbit.api import Fitbit
import fitbit
import discord
import pandas as pd
from oauthlib.oauth2.rfc6749.errors import MismatchingStateError, MissingTokenError

token='YOUR_TOKEN'
class OAuth2Server:
    def __init__(self, client_id, client_secret,
                 redirect_uri='http://127.0.0.1:8080/'):
        """ Initialize the FitbitOauth2Client """
        self.success_html = """
            <h1>You are now authorized to access the Fitbit API!</h1>
            <br/><h3>You can close this window</h3>"""
        self.failure_html = """
            <h1>ERROR: %s</h1><br/><h3>You can close this window</h3>%s"""

        self.fitbit = Fitbit(
            client_id,
            client_secret,
            redirect_uri=redirect_uri,
            timeout=10,
        )

        self.redirect_uri = redirect_uri

    def browser_authorize(self):
        """
        Open a browser to the authorization url and spool up a CherryPy
        server to accept the response
        """
        url, _ = self.fitbit.client.authorize_token_url()
        # Open the web browser in a new thread for command-line browser support
        threading.Timer(1, webbrowser.open, args=(url,)).start()

        # Same with redirect_uri hostname and port.
        urlparams = urlparse(self.redirect_uri)
        cherrypy.config.update({'server.socket_host': urlparams.hostname,
                                'server.socket_port': urlparams.port})

        cherrypy.quickstart(self)

    @cherrypy.expose
    def index(self, state, code=None, error=None):
        """
        Receive a Fitbit response containing a verification code. Use the code
        to fetch the access_token.
        """
        error = None
        if code:
            try:
                self.fitbit.client.fetch_access_token(code)
            except MissingTokenError:
                error = self._fmt_failure(
                    'Missing access token parameter.</br>Please check that '
                    'you are using the correct client_secret')
            except MismatchingStateError:
                error = self._fmt_failure('CSRF Warning! Mismatching state')
        else:
            error = self._fmt_failure('Unknown error while authenticating')
        # Use a thread to shutdown cherrypy so we can return HTML first
        self._shutdown_cherrypy()
        return error if error else self.success_html

    def _fmt_failure(self, message):
        tb = traceback.format_tb(sys.exc_info()[2])
        tb_html = '<pre>%s</pre>' % ('\n'.join(tb)) if tb else ''
        return self.failure_html % (message, tb_html)

    def _shutdown_cherrypy(self):
        """ Shutdown cherrypy in one second, if it's running """
        if cherrypy.engine.state == cherrypy.engine.states.STARTED:
            threading.Timer(1, cherrypy.engine.exit).start()


CLIENT_ID = 'YOUR_CLIENT_ID'
CLIENT_SECRET='YOUR_CLIENT_SECRET'
#(ACCESS_TOKEN,REFRESH_TOKEN) = pickle.load(open('fitbit.pickle','rb'))

server=OAuth2Server(CLIENT_ID, CLIENT_SECRET)
server.browser_authorize()
ACCESS_TOKEN=str(server.fitbit.client.session.token['access_token'])
REFRESH_TOKEN=str(server.fitbit.client.session.token['refresh_token'])

auth2_client=fitbit.Fitbit(CLIENT_ID,CLIENT_SECRET,oauth2=True,access_token=ACCESS_TOKEN,refresh_token=REFRESH_TOKEN)
steps= auth2_client.intraday_time_series('activities/steps')
data = pd.DataFrame(steps['activities-steps-intraday']['dataset'])

total_steps=sum(data['value'].values)
min_steps=0


client= discord.Client()
@client.event
async def on_ready():
    print(f'{client.user}')
@client.event
async def on_message(message):
    global min_steps
    if message.author == client.user:
        return
    if str(message.author) == 'USER#IDNUMBER':
        auth2_client=fitbit.Fitbit(CLIENT_ID,CLIENT_SECRET,oauth2=True,access_token=ACCESS_TOKEN,refresh_token=REFRESH_TOKEN)
        steps= auth2_client.intraday_time_series('activities/steps')
        data = pd.DataFrame(steps['activities-steps-intraday']['dataset'])
       
        total_steps=sum(data['value'].values)
        if total_steps < min_steps:
            await message.delete()
            messag = f'```USER ONLY HAS {total_steps} out of the {min_steps} steps needed to send a message```'.upper()
            await message.channel.send(messag)
        else:
            min_steps+=500
            print(min_steps)


client.run(token)
