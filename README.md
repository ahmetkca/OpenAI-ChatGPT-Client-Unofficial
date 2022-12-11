# Usage:
- `CHATGPT_EMAIL='' CHATGPT_PASSWORD='' CRYPTO_ALGORITHM='' CRYPTO_SECRET_KEY='' npx ts-node src/main.ts`
> 
- `CHATGPT_EMAIL` and `CHATGPT_PASSWORD` are optional. you can use `!login <email> <password>`
> 
- You will have to type `!endMessage` to be able to send your message.
> 
- For example: 
> 
```
❯ CHATGPT_EMAIL='example@gmail.com' CHATGPT_PASSWORD='supersecretpassword' CRYPTO_ALGORITHM='aes-256-ctr' CRYPTO_SECRET_KEY='323C5LoKSAD249abcGLtzaC21dAb4ea' npx ts-node ./src/main.ts
Using cached auth session data
Logged in as example@gmail.com
example@gmail.com #> Hello Assistant!
... This is multiline message
... I will have to type !endMessage to end my multiline input
... for example
... !endMessage
Sending message...
# ChatGPT Response:


-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


Hello! It's nice to meet you. I'm Assistant, a large language model trained by OpenAI. I'm here to help you with any questions you might have. If you have a multiline message, you can simply hit enter after each line to indicate a new line of text. When you're ready to end your message, just type "!endMessage" on its own line and I will receive your entire message. Let me know if you have any other questions.
```

## ChatGPT API interface
- `login({email, password})`
- `sendMessage({input})`
- `refreshThread()`

`sendMessage({})` will maintain the conversation. You don't have to handle `conversation_id` and `parent_message_id`
It will automatically start the conversation and you can reset the conversation by calling `refreshThread()` and you next `sendMessage({input})` call will automatically create a new conversation.

`login({email, password})` will log you in and store auth session data in a encrypted file, so it can use the cached auth session when you launch the app the next time.

enter you messages and when you are done type `!endMessage` to complete your multiline message input.
