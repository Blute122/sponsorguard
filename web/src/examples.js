// The two demo emails are the *actual* test fixtures, imported as raw text so
// the UI and the test suite can never drift apart. Vite's `?raw` suffix returns
// the file contents as a string (see vite.config.js for the fs.allow that lets
// the dev server read outside web/).
import scamRaw from '../../tests/fixtures/scam_nordvpn.eml?raw'
import legitRaw from '../../tests/fixtures/legit_brand.eml?raw'

export const EXAMPLES = [
  {
    key: 'scam',
    label: 'a scam email',
    tone: 'bad',
    hint: 'Fake NordVPN brand deal',
    raw: scamRaw,
  },
  {
    key: 'legit',
    label: 'a real offer',
    tone: 'good',
    hint: 'Real Skillshare outreach',
    raw: legitRaw,
  },
]
