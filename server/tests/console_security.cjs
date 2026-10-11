const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../src/spire_server/static/console.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
const handlers = {};
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, {value: '', innerHTML: '', textContent: '', classList: {add(){}, remove(){}, toggle(){}, contains(){return true;}}});
    return elements.get(id);
  },
  querySelectorAll(){ return []; },
  addEventListener(name, handler){handlers[name] = handler;},
};
const context = vm.createContext({document, localStorage: {removeItem(){}}, setInterval(){}, Date, console});
vm.runInContext(script, context);
const payload = `'"><img src=x onerror=alert(1)>`;
context.payload = payload;
vm.runInContext(`
cache.agents = [{id: payload, hostname: payload}];
cache.events = [{event_id: payload, agent_id: payload, event_type: payload, severity:'high', ts: '2026-10-05', received_at: '2026-10-05', payload:{value:payload}}];
renderEvents();
openEvent(payload);
`, context);
for (const id of ['event-list', 'event-detail']) {
  const rendered = elements.get(id).innerHTML;
  assert(!rendered.includes('<img'), id);
  assert(!rendered.includes('onclick="openAgent'), id);
  assert(!rendered.includes('onclick="openEvent'), id);
  assert(rendered.includes('&lt;img'), id);
}
let clicked;
context.openEvent = id => {clicked = id;};
handlers.click({target:{closest(selector){return selector === '[data-event]' ? {dataset:{event:payload}} : null;}}});
assert.equal(clicked, payload);
assert(!script.includes('localStorage.setItem'));
assert(!html.includes('id="shell-cmd"'));
console.log('Console escaping and event binding regression checks passed');
