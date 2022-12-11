import { ChatGPT } from './ChatGPT/chatgptApi';

import rs from 'node:readline';
import { stdin, stdout } from 'node:process';

import marked from 'marked';
import TerminalRenderer from 'marked-terminal';

const renderMarkdown = (markdown: string) => {
    return marked.marked(markdown, { renderer: new TerminalRenderer() });
}

const logMarkdown = (markdown: string) => {
    console.log(renderMarkdown(markdown));
}

const commandsRegEx: Map<string, RegExp> = new Map([
    ['!help', /!help/],
    ['!quit', /!quit/],
    ['!login', /!login ([a-zA-Z0-9@.]+) ([a-zA-Z0-9]+)/],
    ['!resetThread', /!resetThread/],
    ['!endMessage', /^!endMessage$/],
]);

const quitRegEx = /!quit/

const loginRegEx = /!login ([a-zA-Z0-9@.]+) ([a-zA-Z0-9]+)/

const resetThreadRegEx = /!resetThread/

const endLineRegEx = /^!endline$/




const main = async () => {
    const EMAIL = process.env['CHATGPT_EMAIL'];
    const PASSWORD = process.env['CHATGPT_PASSWORD'];
    const chatGptApi = new ChatGPT();
    const rl = rs.createInterface({ terminal: true ,input: stdin, output: stdout, prompt: '[Not logged in] #> ' });

    if (!EMAIL || !PASSWORD) {
        console.warn('//////////////////////////////////////////////////////////////////////////////////////////')
        console.warn('//\tPlease set the environment variables CHATGPT_EMAIL and CHATGPT_PASSWORD\t\t//');
        console.warn('//\tOr you can use the login function to login with your email and password\t\t//');
        console.warn('//\t\t\t!login <email> <password>\t\t\t\t\t//');
        console.warn('//////////////////////////////////////////////////////////////////////////////////////////')
    } else {
        await chatGptApi.login({
            email: EMAIL,
            password: PASSWORD,
        });
        if (!chatGptApi.isLoggedIn) {
            console.warn('Login with environment variables failed, please try again');
        } else {
            console.log(`Logged in as ${chatGptApi.getLoggedInUser()?.name}`);
            rl.setPrompt(`${chatGptApi.getLoggedInUser()?.name} #> `);
        }
    }

    let lines = '';
    rl.prompt();
    rl.on('line', async (line) => {
        switch (true) {
            case commandsRegEx.get('!help')?.test(line.trim()):
                logMarkdown("# ChatGPT CLI Help: ");
                logMarkdown("---");
                logMarkdown("## Commands: ");
                logMarkdown("### !help");
                logMarkdown("Prints this help message");
                logMarkdown("### !quit");
                logMarkdown("Quits the program");
                logMarkdown("### !login <email> <password>");
                logMarkdown("Logs in with the given email and password");
                logMarkdown("### !resetThread");
                logMarkdown("Resets the conversation thread with ChatGPT and clears the screen");
                logMarkdown("### !endMessage");
                logMarkdown("Sends the message to ChatGPT and prints the response");
                logMarkdown("___");
                rl.setPrompt(`${chatGptApi.getLoggedInUser()?.name} #> `);
                rl.prompt();
                break;
            case commandsRegEx.get('!quit')?.test(line.trim()):
                rl.close();
                break;
            case commandsRegEx.get('!login')?.test(line.trim()):
                const m = loginRegEx.exec(line.trim());
                if (!(m && m.length === 3)) {
                    console.warn('Invalid login command');
                    break;
                }
                if (m) {
                    await chatGptApi.login({
                        email: m[1]!,
                        password: m[2]!,
                    });
                    if (!chatGptApi.isLoggedIn) {
                        console.warn('Login failed, please try again');
                    }
                    rl.setPrompt(`${chatGptApi.getLoggedInUser()?.name} #> `);
                    break;
                }
                console.warn('Invalid login command');
                rl.setPrompt(`${chatGptApi.getLoggedInUser()?.name} #> `);
                rl.prompt();
                break;
            case commandsRegEx.get('!resetThread')?.test(line.trim()):
                chatGptApi.refreshthread();
                if (!(rs.cursorTo(stdout, 0, 0) && rs.clearScreenDown(stdout))) {
                    console.warn('Failed to clear screen');
                }
                rl.setPrompt(`${chatGptApi.getLoggedInUser()?.name} #> `);
                rl.prompt();
                break;
            case commandsRegEx.get('!endMessage')?.test(line.trim()):
                console.log('Sending message...');
                try {
                    const response = await chatGptApi.sendMessage({
                        input: lines.trim(),
                    });
                    if (!response) {
                        console.error('An unknown error occured, please try again');
                        break;
                    }
                    logMarkdown("# ChatGPT Response: ");
                    logMarkdown("---");
                    logMarkdown(response.trim());
                    renderMarkdown("___");
                } catch (e: unknown) {
                    if (e instanceof Error) {
                        console.error(e.message);
                        break;
                    }
                    console.error('An unknown error occured, please try again');
                    console.error(e);
                }
                lines = '';
                rl.setPrompt(`${chatGptApi.getLoggedInUser()?.name} #> `);
                rl.prompt();
                break;
            default:
                rl.setPrompt('... ');
                rl.prompt();
                lines += line;
                lines += ' ';
                break;
        }
    }).on('close', () => {
        console.log('Have a great day!');
        process.exit(0);
    });
}

(async () => {
    await main();
})();
