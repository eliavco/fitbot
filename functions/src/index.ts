import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as express from 'express';
import * as bodyParser from 'body-parser';
import axios from 'axios';
import * as crypto from 'crypto';
import * as qs from 'querystring';

// Initialize Firebase Admin SDK
admin.initializeApp();

const db = admin.firestore();

// Load environment variables
const FACEBOOK_PAGE_ACCESS_TOKEN = ""; //functions.config().facebook.page_access_token;
const FACEBOOK_APP_SECRET = "";  //functions.config().facebook.app_secret;
const VERIFY_TOKEN = "";  //functions.config().facebook.verify_token;
const FITBIT_CLIENT_ID = "";  //functions.config().fitbit.client_id;
const FITBIT_CLIENT_SECRET = "";  //functions.config().fitbit.client_secret;

const app = express();
app.use(bodyParser.json({ verify: verifyRequestSignature }));

// Verify webhook
app.get('/webhook', (req, res) => {
	const mode = req.query['hub.mode'];
	const token = req.query['hub.verify_token'];
	const challenge = req.query['hub.challenge'];

	if (mode === 'subscribe' && token === VERIFY_TOKEN) {
		console.log('WEBHOOK_VERIFIED');
		res.status(200).send(challenge);
	} else {
		res.sendStatus(403);
	}
});

// Handle incoming messages
app.post('/webhook', async (req, res) => {
	const body = req.body;

	if (body.object === 'page') {
		for (const entry of body.entry) {
			const webhook_event = entry.messaging[0];
			const sender_psid = webhook_event.sender.id;

			if (webhook_event.message) {
				await handleMessage(sender_psid, webhook_event.message);
			}
		}
		res.status(200).send('EVENT_RECEIVED');
	} else {
		res.sendStatus(404);
	}
});

// OAuth callback endpoint
app.get('/fitbit/callback', async (req, res) => {
	const code: any = req.query.code;
	const state: any = req.query.state;

	// Exchange authorization code for access token
	const basicAuth = Buffer.from(`${FITBIT_CLIENT_ID}:${FITBIT_CLIENT_SECRET}`).toString('base64');
	try {
		const tokenResponse = await axios.post(
			'https://api.fitbit.com/oauth2/token',
			qs.stringify({
				clientId: FITBIT_CLIENT_ID,
				grant_type: 'authorization_code',
				redirect_uri: functions.config().firebase.function_url + '/fitbit/callback',
				code: code,
			}),
			{
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Authorization: `Basic ${basicAuth}`,
				},
			}
		);

		const { access_token, user_id } = tokenResponse.data;

		// Save access token to Firestore
		await db.collection('users').doc(state).set({
			fitbitUserId: user_id,
			accessToken: access_token,
			congratulated: false,
		});

		res.send('Fitbit account connected! You can return to Messenger.');
	} catch (error) {
		console.error(error);
		res.status(500).send('Error during Fitbit authentication.');
	}
});

// Handle messages
async function handleMessage(sender_psid: string, received_message: any) {
	if (received_message.text) {
		// Check if user is already connected
		const userDoc = await db.collection('users').doc(sender_psid).get();

		if (!userDoc.exists) {
			// Send authorization link
			const authUrl = `https://www.fitbit.com/oauth2/authorize?${qs.stringify({
				response_type: 'code',
				client_id: FITBIT_CLIENT_ID,
				redirect_uri: functions.config().firebase.function_url + '/fitbit/callback',
				scope: 'activity',
				state: sender_psid,
			})}`;

			await callSendAPI(sender_psid, {
				text: `Please connect your Fitbit account: ${authUrl}`,
			});
		} else {
			// Fetch activity data
			const userData: any = userDoc.data();
			const { accessToken, congratulated } = userData;

			if (congratulated) {
				await callSendAPI(sender_psid, {
					text: 'You have already received a congratulations message!',
				});
				return;
			}

			try {
				const lastWeek = new Date();
				lastWeek.setDate(lastWeek.getDate() - 7);
				const lastWeekStr = lastWeek.toISOString().split('T')[0];

				const activitiesResponse = await axios.get(
					`https://api.fitbit.com/1/user/-/activities/list.json?afterDate=${lastWeekStr}&sort=asc&offset=0&limit=1`,
					{
						headers: {
							Authorization: `Bearer ${accessToken}`,
						},
					}
				);

				if (activitiesResponse.data.activities.length > 0) {
					// Send congratulations message
					await callSendAPI(sender_psid, {
						text: 'Congratulations on exercising last week!',
					});

					// Update user document
					await db.collection('users').doc(sender_psid).update({
						congratulated: true,
					});
				} else {
					await callSendAPI(sender_psid, {
						text: 'No exercises found for last week. Keep it up!',
					});
				}
			} catch (error) {
				console.error(error);
				await callSendAPI(sender_psid, {
					text: 'There was an error accessing your Fitbit data.',
				});
			}
		}
	}
}

// Send messages via Send API
async function callSendAPI(sender_psid: string, response: any) {
	try {
		await axios.post(
			`https://graph.facebook.com/v11.0/me/messages?access_token=${FACEBOOK_PAGE_ACCESS_TOKEN}`,
			{
				recipient: { id: sender_psid },
				message: response,
			}
		);
	} catch (error) {
		console.error('Error sending message:', error);
	}
}

// Verify request signature
function verifyRequestSignature(req: any, res: any, buf: any) {
	const signature = req.headers['x-hub-signature-256'];

	if (!signature) {
		console.error('No signature found');
	} else {
		const hash = crypto
			.createHmac('sha256', FACEBOOK_APP_SECRET)
			.update(buf, 'utf-8')
			.digest('hex');
		const expectedHash = `sha256=${hash}`;
		if (signature !== expectedHash) {
			throw new Error('Invalid signature');
		}
	}
}

export const webhook = functions.https.onRequest(app);
