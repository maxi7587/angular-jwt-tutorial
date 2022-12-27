import { TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { AppComponent } from './app.component';
import { AuthService } from "./shared/auth.service";

class MockAuthService {
  doLogout = () => {}
}

describe('AppComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [
        RouterTestingModule
      ],
      declarations: [
        AppComponent
      ],
      providers: [
        { provide: AuthService, useClass: MockAuthService }
      ]
    }).compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('should render title', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h5')?.textContent).toContain('Angular Auth');
  });

  it('should render SignIn', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    const links = compiled.querySelectorAll('a');
    expect(links.item(0).textContent).toContain('Sign in')
  });

  it('' +
    'should logout', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const componentInstance = fixture.componentInstance;
    const logoutSpy = spyOn(componentInstance.authService, 'doLogout');
    fixture.componentInstance.logout();
    expect(logoutSpy).toHaveBeenCalled();
  });
});
