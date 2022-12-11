import { delay, randomMilliseconds, randomNumberBetween } from "./utils";

interface IPipelineStep<I, O> {
    input?: I;
    output?: O;

    process(): Promise<O>;

    setInput(input: I): void;

    getInput(): I | undefined;

    getOutput(): O | undefined;
};

abstract class PipelineStep<I, O> implements IPipelineStep<I, O> {
    input?: I;
    output?: O;

    constructor(input?: I) {
        this.input = input;
    }

    abstract process(): Promise<O>;

    setInput(input: I): void {
        this.input = input;
    }

    getInput(): I | undefined {
        return this.input;
    }

    getOutput(): O | undefined {
        return this.output;
    }
}




/**
 *  Proccesses the given list of steps in order.
 * The output of one step is the input of the next step.
 * That is why the order of the steps are important.
 */
class Pipeline<InitialInput, LastOutput, StepInput = any, StepOutput = any> {
    protected isSuccessfull: boolean = false;
    protected steps: IPipelineStep<StepInput, StepOutput>[] = [];

    constructor({ steps = [], } : {steps: readonly IPipelineStep<StepInput, StepOutput>[]} = { steps: [] }) {
        this.steps = [...steps];
    }

    addStep(step: IPipelineStep<StepInput, StepOutput>): void {
        this.steps.push(step);
    }

    setInitialInput(input: InitialInput): void {
        if (this.steps.length > 0 && this.steps[0]) {
            this.steps[0].setInput(input as unknown as StepInput);
            return;
        }
        console.warn("No steps to set initial input.");
    }

    async run(): Promise<void> {
        if (this.steps.length === 0) {
            throw new Error("No steps to process.");
        }
        let useItForNextStep: any = this.steps[0]?.getInput(); 
        for (const step of this.steps) {
            step.setInput(useItForNextStep);
            const randDelayMs = randomMilliseconds(randomNumberBetween(750, 1500), randomNumberBetween(2500, 5000));
            console.log(`Running step ${step.constructor.name} in ${randDelayMs}ms`);
            await delay(randDelayMs);
            const output = await step.process();
            useItForNextStep = output;
        }
        this.isSuccessfull = true;
    }

    // We know that the last step is the one that returns the last output.
    // So we can safely cast it to the correct type. I hope :)
    getLastStepOutput(): LastOutput {
        return this.steps[this.steps.length - 1]?.getOutput() as LastOutput;
    }

    getIsSuccessfull(): boolean {
        return this.isSuccessfull;
    }

    clear(): void {
        this.steps = [];
    }
}

export { Pipeline, PipelineStep, IPipelineStep };