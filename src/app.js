import pkg from '@slack/bolt';
const { App } = pkg;
import dotenv from 'dotenv';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

dotenv.config();

const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  signingSecret: process.env.SLACK_SIGNING_SECRET,
  socketMode: true,
  appToken: process.env.SLACK_APP_TOKEN,
  port: 3000
});

const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const ALGORITHM = 'aes-256-gcm';
const STORAGE_FILE = './.thread-mappings.enc';
const THREAD_LIFETIME = 30 * 24 * 60 * 60 * 1000;

const threadMappings = new Map();
const messageCache = new Map();

const saveThreadMappings = async () => {
  try {
    const mappingsArray = Array.from(threadMappings.entries());
    const data = JSON.stringify(mappingsArray);
    const encrypted = encrypt(data);
    await fs.writeFile(STORAGE_FILE, JSON.stringify(encrypted), 'utf8');
  } catch (error) {
    console.error('Error saving thread mappings:', {
      error: error.code || 'Unknown error',
      timestamp: new Date().toISOString()
    });
  }
};

const loadThreadMappings = async () => {
  try {
    const fileExists = await fs.access(STORAGE_FILE).then(() => true).catch(() => false);
    if (!fileExists) return;

    const encryptedData = JSON.parse(await fs.readFile(STORAGE_FILE, 'utf8'));
    const decryptedData = decrypt(encryptedData);
    const mappingsArray = JSON.parse(decryptedData);

    threadMappings.clear();

    const now = Date.now();
    for (const [key, value] of mappingsArray) {
      try {
        const mapping = JSON.parse(decrypt(value));
        if (now - mapping.timestamp < THREAD_LIFETIME) {
          threadMappings.set(key, value);
        }
      } catch (error) {
        continue;
      }
    }

    await saveThreadMappings();
  } catch (error) {
    console.error('Error loading thread mappings:', {
      error: error.code || 'Unknown error',
      timestamp: new Date().toISOString()
    });
    threadMappings.clear();
  }
};

loadThreadMappings().then(() => {
  console.log('Thread mappings loaded successfully');
});

setInterval(async () => {
  await saveThreadMappings();
}, 5 * 60 * 1000);

setInterval(async () => {
  const expiryTime = Date.now() - THREAD_LIFETIME;
  let needsSave = false;

  for (const [key, value] of threadMappings.entries()) {
    try {
      const decrypted = JSON.parse(decrypt(value));
      if (decrypted.timestamp < expiryTime) {
        threadMappings.delete(key);
        messageCache.delete(decrypted.channelThreadTs);
        messageCache.delete(decrypted.dmThreadTs);
        needsSave = true;
      }
    } catch (error) {
      threadMappings.delete(key);
      needsSave = true;
    }
  }

  if (needsSave) {
    await saveThreadMappings();
  }
}, 24 * 60 * 60 * 1000);


const generateRandomId = () => {
  return crypto.randomBytes(32).toString('hex');
};

const encrypt = (text) => {
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(64);
  const key = crypto.pbkdf2Sync(ENCRYPTION_KEY, salt, 100000, 32, 'sha512');
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  
  return {
    iv: iv.toString('hex'),
    salt: salt.toString('hex'),
    encrypted: encrypted,
    authTag: authTag.toString('hex')
  };
};

const decrypt = (encryptedData) => {
  const iv = Buffer.from(encryptedData.iv, 'hex');
  const salt = Buffer.from(encryptedData.salt, 'hex');
  const key = crypto.pbkdf2Sync(ENCRYPTION_KEY, salt, 100000, 32, 'sha512');
  
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

const storeThreadMapping = async (channelThreadTs, dmThreadTs, userId, messageId) => {
  const data = JSON.stringify({
    channelThreadTs,
    dmThreadTs,
    userId,
    messageId,
    timestamp: Date.now()
  });
  const encrypted = encrypt(data);
  threadMappings.set(channelThreadTs, encrypted);
  threadMappings.set(dmThreadTs, encrypted);
  
  await saveThreadMappings();
};

const getThreadMapping = (threadTs) => {
  const encrypted = threadMappings.get(threadTs);
  if (!encrypted) return null;
  try {
    const decrypted = decrypt(encrypted);
    return JSON.parse(decrypted);
  } catch (error) {
    threadMappings.delete(threadTs);
    return null;
  }
};



const handleExpiredThread = async (client, event, threadTs) => {
  try {

    const threadHistory = await client.conversations.replies({
      channel: process.env.ANONYMOUS_CHANNEL_ID,
      ts: threadTs
    });

    if (threadHistory.messages && threadHistory.messages.length > 0) {
      const originalMessage = threadHistory.messages[0];

      const anonymousId = originalMessage.username?.split('-')[1];
      
      if (anonymousId) {
        await client.chat.postMessage({
          channel: process.env.ANONYMOUS_CHANNEL_ID,
          thread_ts: threadTs,
          text: "⚠️ This thread is older than 30 days. The original poster may not receive notifications of new replies.",
          username: `Anonymous-${anonymousId}`,
          icon_emoji: ':ghost:'
        });
      }
    }
  } catch (error) {
    console.error('Error handling expired thread:', {
      error: error.code || 'Unknown error',
      timestamp: new Date().toISOString()
    });
  }
};



app.message(async ({ message, client }) => {
  try {
    if (message.channel_type !== 'im' || message.bot_id || message.subtype) return;

    if (message.thread_ts) {
      const threadMapping = getThreadMapping(message.thread_ts);
      if (threadMapping) {
        await client.chat.postMessage({
          channel: process.env.ANONYMOUS_CHANNEL_ID,
          thread_ts: threadMapping.channelThreadTs,
          text: message.text,
          username: `Anonymous-${threadMapping.messageId.substr(0, 8)}`,
          icon_emoji: ':ghost:'
        });
      }
      return;
    }

    await client.chat.postMessage({
      channel: message.channel,
      text: "Do you want to post this message anonymously?",
      thread_ts: message.ts,
      reply_broadcast: true,
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: "Do you want to post this message anonymously?"
          }
        },
        {
          type: "actions",
          elements: [
            {
              type: "button",
              text: {
                type: "plain_text",
                text: "✓ Yes, post it",
                emoji: true
              },
              style: "primary",
              value: message.ts,
              action_id: "post_anonymous"
            },
            {
              type: "button",
              text: {
                type: "plain_text",
                text: "✗ No, cancel",
                emoji: true
              },
              style: "danger",
              value: message.ts,
              action_id: "cancel_post"
            }
          ]
        }
      ]
    });
  } catch (error) {
    console.error('Error in message handler:', error);
  }
});

app.event('message', async ({ event, client }) => {
  try {
    if (event.channel !== process.env.ANONYMOUS_CHANNEL_ID || 
        !event.thread_ts || 
        event.bot_id || 
        event.subtype) return;

    const threadMapping = getThreadMapping(event.thread_ts);
    if (!threadMapping) {
      await handleExpiredThread(client, event, event.thread_ts);
      return;
    }

    const sanitizedReply = sanitizeMessage(event.text);
    await client.chat.postMessage({
      channel: threadMapping.userId,
      thread_ts: threadMapping.dmThreadTs,
      text: `*Reply in thread:*\n${sanitizedReply}`,
      mrkdwn: true
    });
  } catch (error) {
    console.error('Error handling channel reply:', error);
  }
});

app.action('post_anonymous', async ({ ack, body, client }) => {
  await ack();
  try {
    const originalTs = body.actions[0].value;
    
    const result = await client.conversations.replies({
      channel: body.channel.id,
      ts: originalTs,
      limit: 1
    });

    if (!result.messages?.length) return;
    const originalMessage = result.messages[0];

    const messageId = generateRandomId();
    const sanitizedText = sanitizeMessage(originalMessage.text);

    const channelPost = await client.chat.postMessage({
      channel: process.env.ANONYMOUS_CHANNEL_ID,
      text: sanitizedText,
      username: `Anonymous-${messageId.substr(0, 8)}`,
      icon_emoji: ':ghost:'
    });

    await storeThreadMapping(
      channelPost.ts,
      originalTs,
      body.user.id,
      messageId
    );

    await client.chat.update({
      channel: body.channel.id,
      ts: body.message.ts,
      text: "✓ Message posted anonymously. Any replies will appear in this thread.",
      blocks: []
    });

    setTimeout(async () => {
      try {
        await client.chat.delete({
          channel: body.channel.id,
          ts: originalTs
        });
      } catch (error) {
      }
    }, 5000);

  } catch (error) {
    console.error('Error in post_anonymous handler:', error);
    await client.chat.update({
      channel: body.channel.id,
      ts: body.message.ts,
      text: "❌ Failed to post message. Please try again.",
      blocks: []
    });
  }
});

app.action('cancel_post', async ({ ack, body, client }) => {
  await ack();
  try {
    await client.chat.update({
      channel: body.channel.id,
      ts: body.message.ts,
      text: "✗ Message cancelled.",
      blocks: []
    });
  } catch (error) {
    console.error('Error in cancel_post handler:', error);
  }
});


app.error(async (error) => {
  console.error('Application error:', {
    code: error.code || 'Unknown error',
    timestamp: new Date().toISOString()
  });
});


process.on('SIGTERM', async () => {
  console.log('Received SIGTERM signal, cleaning up...');

  await saveThreadMappings();

  threadMappings.clear();
  messageCache.clear();
  process.exit(0);
});


process.on('SIGINT', async () => {
  console.log('Received SIGINT signal, cleaning up...');
  await saveThreadMappings();
  threadMappings.clear();
  messageCache.clear();
  process.exit(0);
});


(async () => {
  try {
    await app.start();
    console.log('bot is running');
  } catch (error) {
    console.error('Unable to start app:', {
      error: error.code || 'Unknown error',
      timestamp: new Date().toISOString()
    });
    process.exit(1);
  }
})(); 