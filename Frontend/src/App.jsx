import Header from './components/Layout/Header';
import Footer from './components/Layout/Footer';
import StepUpDialog from './components/auth/StepUpDialog';
import PreviewBanner from './components/preview/PreviewBanner';
import PreviewInbox from './components/preview/PreviewInbox';
import RouterComponent from './router/RouterComponent';
import { IS_PREVIEW } from './config';

function App() {
  return (
    <>
      <a className="skip-link" href="#main">Skip to main content</a>
      {IS_PREVIEW && <PreviewBanner />}
      <Header />
      <main id="main" tabIndex={-1}>
        <RouterComponent />
      </main>
      <Footer />
      <StepUpDialog />
      {IS_PREVIEW && <PreviewInbox />}
    </>
  );
}

export default App;
