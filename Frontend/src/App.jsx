import Header from './components/Layout/Header';
import Footer from './components/Layout/Footer';
import DemoBanner from './components/demo/DemoBanner';
import DemoInbox from './components/demo/DemoInbox';
import RouterComponent from './router/RouterComponent';
import { IS_DEMO } from './config';

function App() {
  return (
    <>
      <a className="skip-link" href="#main">Skip to main content</a>
      {IS_DEMO && <DemoBanner />}
      <Header />
      <main id="main" tabIndex={-1}>
        <RouterComponent />
      </main>
      <Footer />
      {IS_DEMO && <DemoInbox />}
    </>
  );
}

export default App;
