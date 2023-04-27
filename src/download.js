const saveFile = () => {
  // Get the data from each element on the form.
  const data = document.querySelector('.outputTextarea').value;
  const button = document.querySelector('.downloadButt');
  //   console.log(data);
  // Convert the text to BLOB.
  const textToBLOB = new Blob([data], { type: 'text/plain' });
  const sFileName = 'data.txt'; // The file to save the data.

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
