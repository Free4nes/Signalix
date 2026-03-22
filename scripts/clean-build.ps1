Write-Host "Cleaning Expo / Gradle build artifacts..."

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue android\.gradle
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue android\build
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue android\app\build

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .expo
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .expo-shared

npm cache clean --force

Write-Host "Cleanup complete."
