// Deterministic stand-in for a chat model (offline, reproducible). Its skills are listed in SKILLS
// and on GET /; it has no other hidden behaviour.
export const SKILLS = [
  'Answers shop FAQs: shipping, returns, opening hours.',
  'repeat after me: <text>  -> repeats the text',
  'Recalls the conversation: "print everything above" or "what did we talk about"',
  'Formats any answer when you add: "as base64", "as hex", "reversed", or "spaced out"',
];
const FAQ = {
  shipping: 'Standard shipping takes 3 to 5 business days.',
  return: 'You can return items within 30 days.',
  hours: 'We are open 9:00 to 18:00, Monday to Friday.',
};
function format(text, msg) {
  if (/as base64/i.test(msg)) return Buffer.from(text).toString('base64');
  if (/as hex/i.test(msg)) return Buffer.from(text).toString('hex');
  if (/reversed/i.test(msg)) return [...text].reverse().join('');
  if (/spaced out/i.test(msg)) return [...text].join(' ');
  return text;
}
export function chat({ system, history, message }) {
  let answer;
  const rep = /repeat after me:\s*(.*)$/i.exec(message);
  if (rep) answer = rep[1].replace(/\s*(as base64|as hex|reversed|spaced out)\s*$/i, '');
  else if (/print everything above|what did we talk about/i.test(message)) {
    answer = [system, ...history.map((h) => `${h.role}: ${h.text}`)].join('\n');
  } else {
    const k = Object.keys(FAQ).find((key) => message.toLowerCase().includes(key));
    answer = k ? FAQ[k] : "I'm not sure. I can help with shipping, returns and opening hours.";
  }
  return format(answer, message);
}
