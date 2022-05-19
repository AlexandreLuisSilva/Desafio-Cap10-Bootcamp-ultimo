import { ReactComponent as AuthImage } from 'assets/images/auth-image.svg';
import { useEffect } from 'react';
import { isAuthenticated } from 'util/auth';
import history from 'util/history';
import Login from './Login';
import './styles.css';

const Auth = () => {

  useEffect(() => {
    if (isAuthenticated()) {
        history.push('/movies')
    }
  }, []);

  return (
    <div className="auth-container">
      <div className="auth-banner-container">
        <h1>Avalie Filmes</h1>
        <p>Diga o que você achou do seu filme favorito</p>
        <AuthImage />
      </div>
      <div className="auth-form-container">
        <Login />
      </div>
    </div>
  );
};

export default Auth;
