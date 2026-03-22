/**
 * Image optimization for chat uploads.
 * Resizes and compresses images before upload to reduce bandwidth and storage.
 */
import { Image } from "react-native";
import * as ImageManipulator from "expo-image-manipulator";
import * as FileSystem from "expo-file-system";

const MAX_LONGEST_SIDE = 1200;
const JPEG_QUALITY = 0.82;

export interface OptimizeResult {
  uri: string;
  mimeType: string;
  width?: number;
  height?: number;
  sizeBytes?: number;
}

function getImageDimensions(uri: string): Promise<{ width: number; height: number } | null> {
  return new Promise((resolve) => {
    Image.getSize(
      uri,
      (width, height) => resolve({ width, height }),
      () => resolve(null)
    );
  });
}

/**
 * Optimizes an image for upload: resize to max 1200px longest side, compress as JPEG.
 * On failure, returns the original URI with mimeType (caller can still upload).
 */
export async function optimizeImageForUpload(
  uri: string,
  mimeType: string
): Promise<OptimizeResult> {
  try {
    const dims = await getImageDimensions(uri);
    const actions: ImageManipulator.Action[] = [];
    if (dims && (dims.width > MAX_LONGEST_SIDE || dims.height > MAX_LONGEST_SIDE)) {
      const resize =
        dims.width >= dims.height
          ? { width: MAX_LONGEST_SIDE }
          : { height: MAX_LONGEST_SIDE };
      actions.push({ resize });
    }
    const result = await ImageManipulator.manipulateAsync(uri, actions, {
      compress: JPEG_QUALITY,
      format: ImageManipulator.SaveFormat.JPEG,
    });

    let sizeBytes: number | undefined;
    try {
      const info = await FileSystem.getInfoAsync(result.uri, { size: true });
      if (info.exists && "size" in info && typeof info.size === "number") {
        sizeBytes = info.size;
      }
    } catch {
      // Ignore – size is optional for logging
    }

    return {
      uri: result.uri,
      mimeType: "image/jpeg",
      width: result.width,
      height: result.height,
      sizeBytes,
    };
  } catch (e) {
    if (__DEV__) console.log("IMAGE_OPTIMIZED_FAILED", e);
    return { uri, mimeType };
  }
}

/**
 * Returns file size in bytes for a local URI, or undefined if not available.
 */
export async function getFileSize(uri: string): Promise<number | undefined> {
  try {
    const info = await FileSystem.getInfoAsync(uri, { size: true });
    if (info.exists && "size" in info && typeof info.size === "number") {
      return info.size;
    }
  } catch {
    // Ignore
  }
  return undefined;
}
