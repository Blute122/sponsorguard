// The demo emails are the *actual* test fixtures and eval corpus, imported as
// raw text so the UI, the tests and the eval harness can never drift apart.
// Vite's `?raw` query returns the file contents as a string (see
// vite.config.js for the fs.allow that lets the dev server read outside web/).
import scamRaw from '../../tests/fixtures/scam_nordvpn.eml?raw'
import legitRaw from '../../tests/fixtures/legit_brand.eml?raw'

export const EXAMPLES = [
  {
    key: 'scam',
    label: 'Fake NordVPN offer',
    tone: 'bad',
    raw: scamRaw,
  },
  {
    key: 'legit',
    label: 'Genuine Skillshare outreach',
    tone: 'good',
    raw: legitRaw,
  },
]

// The labelled eval corpus doubles as a sample inbox for the triage queue.
// Only file names are shown — the scam/legit folder is not surfaced, so the
// queue's verdicts come from the engine, not from the label.
const corpus = import.meta.glob('../../eval/corpus/*/*.eml', {
  query: '?raw',
  import: 'default',
  eager: true,
})

export const SAMPLE_INBOX = Object.entries(corpus)
  .map(([path, raw]) => ({ name: path.split('/').pop(), raw }))
  .sort((a, b) => a.name.localeCompare(b.name))
