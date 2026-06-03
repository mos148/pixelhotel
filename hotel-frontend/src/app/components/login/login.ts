import { Component, ChangeDetectorRef } from '@angular/core';
import { AuthService } from '../../services/auth';
import { RouterLink, Router } from '@angular/router';

@Component({
  selector: 'app-login',
  standalone: true,
  templateUrl: './login.html',
  styleUrls: ['./login.css'],
  imports: [RouterLink],
})
export class LoginComponent {
  mensajeError: string = '';
  isError: boolean = false;
  isSuccess: boolean = false;

  constructor(
    private authService: AuthService,
    private router: Router,
    private cdr: ChangeDetectorRef,
  ) {}

  async iniciarSesion(email: string, pass: string) {
    if (!email || !pass) {
      this.isError = true;
      this.isSuccess = false;
      this.mensajeError = 'Por favor, rellena todos los campos.';
      this.cdr.detectChanges();
      return;
    }

    this.isError = false;
    this.isSuccess = false;
    this.mensajeError = 'Enviando login...';
    this.cdr.detectChanges(); 

    try {
      const json = await this.authService.login({ email: email, password: pass }).toPromise();

      if (json?.ok) {
        this.isSuccess = true;
        this.mensajeError = '¡Login correcto! Redirigiendo...';
        this.cdr.detectChanges();
        setTimeout(() => this.router.navigate(['/home']), 1000);
      } else {
        this.isError = true;
        this.mensajeError = json?.error || 'Email o contraseña incorrectos.';
        this.cdr.detectChanges();
      }
    } catch (err) {
      this.isError = true;
      this.mensajeError = 'Email o contraseña incorrectos.';
      this.cdr.detectChanges();
      console.error('Login error:', err);
    }
  }
}
