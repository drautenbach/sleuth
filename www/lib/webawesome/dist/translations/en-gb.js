/*! Copyright 2026 Fonticons, Inc. - https://webawesome.com/license */
import {
  registerTranslation
} from "../chunks/chunk.WDXLBFVK.js";
import {
  en_default
} from "../chunks/chunk.Q2PL34ZC.js";
import "../chunks/chunk.7VGCIHDG.js";

// src/translations/en-gb.ts
var translation = {
  ...en_default,
  $code: "en-GB",
  $name: "English (United Kingdom)",
  captions: "Captions",
  enterFullscreen: "Enter fullscreen",
  exitFullscreen: "Exit fullscreen",
  mute: "Mute",
  nextVideo: "Next video",
  pause: "Pause",
  pictureInPicture: "Picture in picture",
  play: "Play",
  playbackSpeed: "Playback speed",
  playlist: "Playlist",
  previousVideo: "Previous video",
  selectAColorFromTheScreen: "Select a colour from the screen",
  toggleColorFormat: "Toggle colour format",
  seek: "Seek",
  seekProgress: (current, duration) => `${current} of ${duration}`,
  currentlyPlaying: "currently playing",
  unmute: "Unmute",
  videoPlayer: "Video player",
  volume: "Volume"
};
registerTranslation(translation);
var en_gb_default = translation;
export {
  en_gb_default as default
};
