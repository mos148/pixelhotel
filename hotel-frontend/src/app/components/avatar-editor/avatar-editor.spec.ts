import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AvatarEditor } from './avatar-editor';

describe('AvatarEditor', () => {
  let component: AvatarEditor;
  let fixture: ComponentFixture<AvatarEditor>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AvatarEditor]
    })
    .compileComponents();

    fixture = TestBed.createComponent(AvatarEditor);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
