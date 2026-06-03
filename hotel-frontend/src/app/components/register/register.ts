import { Component, ChangeDetectorRef } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { AuthService } from '../../services/auth';
import { Router, RouterLink } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [ReactiveFormsModule, RouterLink, CommonModule],
  templateUrl: './register.html',
  styleUrls: ['./register.css'],
})
export class RegisterComponent {
  registerForm: FormGroup;
  mensaje: string = '';
  isError: boolean = false;
  isSuccess: boolean = false;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    private cdr: ChangeDetectorRef,
  ) {
    this.registerForm = this.fb.group({
      nickname: ['', [Validators.required, Validators.maxLength(12)]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
      birth_date: ['', Validators.required],
    });
  }

  async registrarse() {
    if (!this.registerForm.valid) {
      this.registerForm.markAllAsTouched();

      this.isError = true;
      this.isSuccess = false;
      this.mensaje = 'Por favor, corrige los errores del formulario.';

      return;
    }

    this.isError = false;
    this.isSuccess = false;
    this.mensaje = 'Creando cuenta...';

    this.authService.register(this.registerForm.value).subscribe({
      next: (res: any) => {
        this.isSuccess = true;
        this.mensaje = '¡Registro exitoso! Redirigiendo...';

        setTimeout(() => this.router.navigate(['/login']), 1500);
      },
      error: (err) => {
        this.isError = true;
        this.mensaje = err.error?.error || 'Error al crear la cuenta. Inténtalo de nuevo.';
      },
    });
  }
}
