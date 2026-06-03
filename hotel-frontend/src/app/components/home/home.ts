import { Component, OnInit, ChangeDetectorRef } from '@angular/core'; 
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../services/auth';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-home',
  standalone: true,
  templateUrl: './home.html',
  styleUrls: ['./home.css'],
  imports: [CommonModule, RouterLink]
})
export class HomeComponent implements OnInit {
  meNick: string = 'Cargando...';
  meCreditos: number = 0;
  meAvatarUrl: string = 'assets/base_avatar.png';
  statusMessage: string = '';

  constructor(
    private authService: AuthService, 
    private router: Router,
    private cdr: ChangeDetectorRef 
  ) {}

  ngOnInit() {
    this.loadUser();
  }

  loadUser() {
    this.authService.getMe().subscribe({
      next: (res: any) => {
        if (res.ok && res.user) {
          
          this.meNick = res.user.nickname || 'Usuario Invitado';
          this.meCreditos = res.user.creditos || 0;

          this.meAvatarUrl = `http://localhost:3000/api/users/${res.user.id}/avatar?t=${new Date().getTime()}`;

          this.cdr.detectChanges();
        } else {
          this.router.navigate(['/login']);
        }
      },
      error: () => this.router.navigate(['/login'])
    });
  }

  enterHotel() {
    this.router.navigate(['/hotel']);
  }

  logout() {
    this.authService.logout().subscribe({
      next: () => this.router.navigate(['/login']),
      error: () => this.router.navigate(['/login'])
    });
  }
}