const saveFile = () => {
  const data = document.querySelector('.outputTextarea').value;
  const textToBLOB = new Blob([data], { type: 'text/plain' });
  const sFileName = 'data.txt';

  const newLink = document.createElement('a');
  newLink.download = sFileName;

  if (window.webkitURL != null) {
    newLink.href = window.webkitURL.createObjectURL(textToBLOB);
  } else {
    newLink.href = window.URL.createObjectURL(textToBLOB);
    newLink.style.display = 'none';
    document.body.appendChild(newLink);
  }

  newLink.click();
};

export default saveFile;
