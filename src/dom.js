import ciphers from './logic';

function createHeader() {
  const header = document.createElement('div');
  const title = document.createElement('h1');

  header.classList = 'header';
  title.textContent = 'ENCODE/DECODE';
  header.appendChild(title);

  return header;
}

function createMain() {
  const main = document.createElement('div');
  //   const mainProjectTitle = document.createElement('h2');
  const mainContent = document.createElement('div');

  mainContent.classList = 'main-content';

  //   mainProjectTitle.classList = 'main-title';
  //   mainProjectTitle.textContent = '';
  main.classList = 'main';

  //   main.appendChild(mainProjectTitle);

  main.appendChild(mainContent);

  return main;
}

function createFooter() {
  const footer = document.createElement('div');
  footer.innerHTML = '<p>Created by <a href="https://github.com/wojwoj8">wojwoj8</a></p>';
  footer.classList = 'footer';
  return footer;
}

function createMainContent() {
  const mainContent = document.querySelector('.main-content');
  const inputDiv = document.createElement('div');
  inputDiv.classList = 'inputDiv';
  const outputDiv = document.createElement('div');
  outputDiv.classList = 'outputDiv';
  const inputTextarea = document.createElement('textarea');
  const outputTextarea = document.createElement('textarea');

  const inputP = document.createElement('p');
  const outputP = document.createElement('p');

  inputP.innerHTML = '<label for="inputTextarea">Input:</label>';
  outputP.innerHTML = '<label for="outputTextarea">Output:</label>';

  inputTextarea.classList = 'inputTextarea';
  inputTextarea.setAttribute('name', 'inputTextarea');
  outputTextarea.classList = 'outputTextarea';
  outputTextarea.setAttribute('name', 'outputTextarea');
  const select = document.createElement('select');
  select.id = 'cipher-select';
  select.innerHTML = `
  <select id="cipher-select">
    <option value="aes">AES</option>
    <option value="des">DES</option>
    <option value="rc4">RC4</option>
    <option value="md5">MD5</option>
    <option value="sha256">SHA256</option>
    <option value="sha512">SHA512</option>
  </select>`;

  select.addEventListener('change', selectHandler);

  inputDiv.appendChild(inputP);
  inputDiv.appendChild(inputTextarea);
  outputDiv.appendChild(outputP);
  outputDiv.appendChild(outputTextarea);
  mainContent.appendChild(inputDiv);
  mainContent.appendChild(select);
  mainContent.appendChild(outputDiv);
}

function createButtons() {
  const main = document.querySelector('.main');
  const buttonsDiv = document.createElement('div');
  buttonsDiv.classList = 'buttonDiv';
  const button = document.createElement('button');
  button.textContent = 'encrypt';
  buttonsDiv.appendChild(button);
  button.addEventListener('click', inputHandler);
  main.appendChild(buttonsDiv);
}
function selectHandler() {
  const cipherSelect = document.querySelector('#cipher-select');
  const selectedCipher = cipherSelect.value;
  const inputDiv = document.querySelector('.inputDiv');
  let keyInput = null;

  const existingKeyInput = inputDiv.querySelector('.keyInput');
  if (existingKeyInput) {
    existingKeyInput.parentNode.remove();
  }

  if (selectedCipher === 'aes' || selectedCipher === 'des' || selectedCipher === 'rc4') {
    const cont = document.createElement('div');
    keyInput = document.createElement('input');
    keyInput.classList = 'keyInput';
    keyInput.setAttribute('name', 'additionalInputTextarea');

    const inputLabel = document.createElement('label');
    inputLabel.setAttribute('for', 'additionalInputTextarea');
    inputLabel.textContent = 'Enter key:';

    cont.appendChild(inputLabel);
    cont.appendChild(keyInput);
    inputDiv.appendChild(cont);
  }
}

function inputHandler() {
  const input = document.querySelector('.inputTextarea');
  const output = document.querySelector('.outputTextarea');
  const cipherSelect = document.querySelector('#cipher-select');
  const selectedCipher = cipherSelect.value;
  const inputValue = input.value;
  const inputDiv = document.querySelector('.inputDiv');
  const cont = document.createElement('div');
  let keyInput = null;

  if (selectedCipher === 'aes' || selectedCipher === 'des' || selectedCipher === 'rc4') {
    keyInput = document.createElement('input');
    keyInput.classList = 'keyInput';
    keyInput.setAttribute('name', 'additionalInputTextarea');

    const inputLabel = document.createElement('label');
    inputLabel.setAttribute('for', 'additionalInputTextarea');
    inputLabel.textContent = 'Enter key:';

    cont.appendChild(inputLabel);
    cont.appendChild(keyInput);
    inputDiv.appendChild(cont);
  } else if (cont) {
    cont.remove();
  }

  console.log(inputValue);
  console.log(selectedCipher);
}

function webInit() {
  const content = document.querySelector('#content');
  content.appendChild(createHeader());
  content.appendChild(createMain());
  content.appendChild(createFooter());
  createMainContent();
  createButtons();
  return content;
}
export default webInit;
