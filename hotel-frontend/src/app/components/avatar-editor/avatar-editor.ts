import { Component, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-avatar-editor',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './avatar-editor.html',
  styleUrls: ['./avatar-editor.css']
})
export class AvatarEditorComponent {
  @Output() colorCambiado = new EventEmitter<{tipo: 'shirt' | 'pant' | 'shoes' | 'hair', color: number}>();
  @Output() cerrarMenu = new EventEmitter<void>();

  colores: number[] = [
    0xFFFFFF, 0xDDDDDD, 0x999999, 0x444444, 0x111111,
    0xFF5555, 0xFF9999, 0xFFBB55, 0xFFFF55, 0x99FF99,
    0x55FF55, 0x118811, 0x55FFFF, 0x5599FF, 0x0000AA,
    0x9955FF, 0xFF55FF, 0xFF99FF, 0x8B4513, 0xD2B48C
  ];

  // Estado del editor
  tipoSeleccionado: 'shirt' | 'pant' | 'shoes' | 'hair' = 'shirt';
  colorCamisa: number = 0x808080;
  colorPantalon: number = 0x0000ff;
  colorZapatos: number = 0x2b2b2b;
  colorPelo: number = 0x8B4513;

  seleccionarColor(color: number) {
    if (this.tipoSeleccionado === 'shirt') {
      this.colorCamisa = color;
    } else if (this.tipoSeleccionado === 'pant') {
      this.colorPantalon = color;
    } else if (this.tipoSeleccionado === 'shoes') {
      this.colorZapatos = color;
    } else if (this.tipoSeleccionado === 'hair') {
      this.colorPelo = color;
    }
    this.colorCambiado.emit({ tipo: this.tipoSeleccionado, color: color });
  }

  cerrar() { this.cerrarMenu.emit(); }

  getHex(color: number): string {
    return '#' + color.toString(16).padStart(6, '0');
  }
}