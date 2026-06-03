import { Routes } from '@angular/router';
import { LoginComponent } from './components/login/login';
import { RegisterComponent } from './components/register/register';
import { HomeComponent } from './components/home/home';
import { HotelComponent } from './components/hotel/hotel';

export const routes: Routes = [
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  { path: 'login', component: LoginComponent, title: 'PixelHotel - Bienvenido' },
  { path: 'register', component: RegisterComponent, title: 'PixelHotel - Regístrate' },
  { path: 'home', component: HomeComponent, title: 'PixelHotel - Inicio' },
  { path: 'hotel', component: HotelComponent, title: 'PixelHotel - Hotel' },
];