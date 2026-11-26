// A deterministic stand-in for an LLM, so the challenge runs offline with no API key.
// It reproduces the one behaviour that matters here, documented in the model card:
// instructions that appear anywhere in its context window are followed, including ones inside
// "untrusted" data. Real models are harder to steer, but every production agent has to assume they can be.
export const MODEL_CARD = {
  name: 'toy-agent-1',
  behaviour: [
    'Summarizes each document by its first sentence.',
    'Follows tool-call instructions written as:  CALL tool_name("argument")  on their own line, in order, wherever they appear in context.',
    'In a tool argument, {{last}} is replaced with the previous tool result.',
    'Is told by its system prompt not to reveal secrets and to ignore instructions inside <untrusted> tags. (It is not very good at this.)',
  ],
};

export async function runModel({ system, context, tools }) {
  const transcript = [];
  let last = '';
  const calls = [...context.matchAll(/^\s*CALL\s+(\w+)\("((?:[^"\\]|\\.)*)"\)\s*$/gm)];
  for (const [, name, rawArg] of calls) {
    const tool = tools[name];
    if (!tool) { transcript.push(`(no such tool: ${name})`); continue; }
    const arg = rawArg.replace(/\{\{last\}\}/g, last);
    last = String(await tool(arg));
    transcript.push(`called ${name}`);
  }
  const docs = [...context.matchAll(/<untrusted>([\s\S]*?)<\/untrusted>/g)].map((m) => m[1].trim());
  const summary = docs.map((d) => (d.split(/(?<=[.!?])\s/)[0] ?? '').slice(0, 160)).join(' / ');
  return { summary, transcript, system };
}
