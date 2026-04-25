const topicEl = document.getElementById('topic');
const proNameEl = document.getElementById('proName');
const conNameEl = document.getElementById('conName');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const messagesEl = document.getElementById('messages');
const voteA = document.getElementById('voteA');
const voteB = document.getElementById('voteB');
const voteResult = document.getElementById('voteResult');

let stream = null;
let debateId = null;
let votes = { a: 0, b: 0 };

function addMessage(type, name, text) {
  const item = document.createElement('div');
  item.className = `bubble ${type}`;
  item.innerHTML = `<span class="name">${name}</span><span>${text}</span>`;
  messagesEl.appendChild(item);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function resetVote() {
  votes = { a: 0, b: 0 };
  voteResult.textContent = 'Belum ada vote.';
}

function renderVote() {
  const total = votes.a + votes.b;
  if (!total) {
    voteResult.textContent = 'Belum ada vote.';
    return;
  }
  const pA = Math.round((votes.a / total) * 100);
  const pB = 100 - pA;
  const win = pA === pB ? 'Seri' : pA > pB ? proNameEl.value || 'Tim A' : conNameEl.value || 'Tim B';
  voteResult.textContent = `${proNameEl.value}: ${pA}% | ${conNameEl.value}: ${pB}% — Unggul: ${win}`;
}

async function stopDebate() {
  if (stream) {
    stream.close();
    stream = null;
  }
  if (debateId) {
    await fetch('/api/debate/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ debateId })
    }).catch(() => null);
    debateId = null;
  }
  startBtn.disabled = false;
  stopBtn.disabled = true;
}

startBtn.addEventListener('click', async () => {
  const topic = topicEl.value.trim();
  if (!topic) {
    alert('Isi topik dulu.');
    return;
  }

  await stopDebate();
  resetVote();
  messagesEl.innerHTML = '';

  const params = new URLSearchParams({
    topic,
    proName: proNameEl.value.trim() || 'Tim A',
    conName: conNameEl.value.trim() || 'Tim B'
  });

  stream = new EventSource(`/api/debate/stream?${params.toString()}`);
  startBtn.disabled = true;
  stopBtn.disabled = false;

  stream.onmessage = ev => {
    const data = JSON.parse(ev.data);

    if (data.status === 'started') {
      debateId = data.debateId;
      return;
    }

    if (data.type === 'turn') {
      addMessage(data.speaker, data.speakerName, data.text);
      return;
    }

    if (data.type === 'error') {
      addMessage('con', 'System', data.message);
      stopDebate();
      return;
    }

    if (data.type === 'done') {
      stopDebate();
    }
  };

  stream.onerror = () => {
    addMessage('con', 'System', 'Koneksi putus. Coba mulai lagi.');
    stopDebate();
  };
});

stopBtn.addEventListener('click', stopDebate);
voteA.addEventListener('click', () => {
  votes.a += 1;
  renderVote();
});
voteB.addEventListener('click', () => {
  votes.b += 1;
  renderVote();
});
