import React from 'react';
import Login from './components/Login';
import Registration from './components/Registration';
 
function App() {
    return (
        <div className="App">
            <div style={centerStyle}>
                <h1>
                    MFA using
                    MERN Stack
                </h1>
            </div>
            <Login />
            <Registration/>
        </div>
    );
}
 
const centerStyle = {
    textAlign: 'center',
};
export default App;