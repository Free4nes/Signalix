# Clean build caches (EAS upload / ENOSPC)

Run from **mobile/** or use full paths to **mobile/android/**.

## Windows (PowerShell)

```powershell
Remove-Item -Recurse -Force android\.gradle -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force android\build -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force android\app\build -ErrorAction SilentlyContinue
npm cache clean --force
```

## EAS build

```bash
eas build -p android --profile preview
```
