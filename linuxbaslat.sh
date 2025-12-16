if [ ! -d "node_modules" ]; then
    npm install
else
fi
npx electron .